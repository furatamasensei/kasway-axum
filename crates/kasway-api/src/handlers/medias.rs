//! `/api/media` — MediasController. Merchant upload/delete. Bytes go to a storage
//! disk: Adonis uses R2/S3, the port writes to a local filesystem disk (same row
//! contract). Compression (sharp/ffmpeg) is best-effort and a no-op here, matching
//! the Adonis "compression failed → keep original size" path.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

const IMAGE_EXTENSIONS: &[&str] = &["jpg", "jpeg", "png", "gif"];
const VIDEO_EXTENSIONS: &[&str] = &["mp4", "mov", "avi", "mkv"];
const MAX_SIZE: usize = 100 * 1024 * 1024; // 100mb

fn media_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("kasway-media")
}

#[derive(sqlx::FromRow)]
struct MediaRow {
    id: i64,
    user_id: i64,
    key: String,
    media_type: String,
    status: String,
    size: i64,
    width: Option<i64>,
    height: Option<i64>,
    duration: Option<i64>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

fn serialize_media(m: &MediaRow) -> Value {
    json!({
        "id": m.id,
        "userId": m.user_id,
        "key": m.key,
        "mediaType": m.media_type,
        "status": m.status,
        "size": m.size,
        "width": m.width,
        "height": m.height,
        "duration": m.duration,
        "createdAt": m.created_at,
        "updatedAt": m.updated_at,
    })
}

fn vfail(field: &str, rule: &str, msg: &str) -> AppError {
    AppError::Validation(vec![ValidationFailure { message: msg.into(), rule: rule.into(), field: field.into() }])
}

/// `POST /api/media` (merchant) — multipart upload.
pub async fn store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_ext: Option<String> = None;
    let (mut width, mut height, mut duration): (Option<i64>, Option<i64>, Option<i64>) = (None, None, None);

    while let Some(field) = multipart.next_field().await.map_err(|_| vfail("file", "file", "Invalid multipart payload"))? {
        match field.name().map(|s| s.to_string()).as_deref() {
            Some("file") => {
                let ext = field.file_name()
                    .and_then(|f| f.rsplit('.').next())
                    .map(|e| e.to_ascii_lowercase());
                file_ext = ext;
                let data = field.bytes().await.map_err(|_| vfail("file", "file", "Could not read uploaded file"))?;
                file_bytes = Some(data.to_vec());
            }
            Some("width") => width = field.text().await.ok().and_then(|t| t.trim().parse().ok()),
            Some("height") => height = field.text().await.ok().and_then(|t| t.trim().parse().ok()),
            Some("duration") => duration = field.text().await.ok().and_then(|t| t.trim().parse().ok()),
            _ => { let _ = field.bytes().await; }
        }
    }

    let bytes = file_bytes.ok_or_else(|| vfail("file", "required", "The file field must be defined"))?;
    if bytes.len() > MAX_SIZE {
        return Err(vfail("file", "size", "The file size must be under 100mb"));
    }
    let ext = file_ext.filter(|e| !e.is_empty())
        .filter(|e| IMAGE_EXTENSIONS.contains(&e.as_str()) || VIDEO_EXTENSIONS.contains(&e.as_str()))
        .ok_or_else(|| vfail("file", "extname", "The file must have one of the allowed extensions"))?;

    let is_image = IMAGE_EXTENSIONS.contains(&ext.as_str());
    let media_type = if is_image { "image" } else { "video" };
    let folder = if is_image { "images" } else { "videos" };
    let key = format!("media/{folder}/{}.{ext}", uuid::Uuid::new_v4());

    // compression is best-effort (no-op here) → size stays the uploaded length
    let size = bytes.len() as i64;

    // write to the filesystem storage disk
    let path = media_dir().join(&key);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| AppError::commerce(500, "Storage write failed"))?;
    }
    std::fs::write(&path, &bytes).map_err(|_| AppError::commerce(500, "Storage write failed"))?;

    let now = now_iso();
    let id = sqlx::query(
        "INSERT INTO media (user_id, key, media_type, status, size, width, height, duration, created_at, updated_at) \
         VALUES (?, ?, ?, 'uploaded', ?, ?, ?, ?, ?, ?)",
    )
    .bind(auth.user_id).bind(&key).bind(media_type).bind(size).bind(width).bind(height).bind(duration)
    .bind(&now).bind(&now)
    .execute(&state.db.pool).await?
    .last_insert_rowid();

    let row = sqlx::query_as::<_, MediaRow>(
        "SELECT id, user_id, key, media_type, status, size, width, height, duration, created_at, updated_at FROM media WHERE id = ?",
    ).bind(id).fetch_one(&state.db.pool).await?;
    Ok((StatusCode::CREATED, Json(serialize_media(&row))).into_response())
}

/// `DELETE /api/media/:id` (merchant)
pub async fn destroy(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Response> {
    let key: Option<String> = sqlx::query_scalar("SELECT key FROM media WHERE user_id = ? AND id = ?")
        .bind(auth.user_id).bind(id).fetch_optional(&state.db.pool).await?;
    let Some(key) = key else {
        return Err(AppError::commerce(404, "Media not found"));
    };
    sqlx::query("DELETE FROM media WHERE id = ?").bind(id).execute(&state.db.pool).await?;
    // best-effort storage delete (@beforeDelete hook)
    let _ = std::fs::remove_file(media_dir().join(&key));
    Ok(StatusCode::NO_CONTENT.into_response())
}
