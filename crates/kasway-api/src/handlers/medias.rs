//! `/api/media` — MediasController. Merchant upload/delete. Bytes go to a storage
//! disk: Adonis uses R2/S3, the port writes to a local filesystem disk (same row
//! contract). Compression (sharp/ffmpeg) is best-effort and a no-op here, matching
//! the Adonis "compression failed → keep original size" path.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use serde_json::Value;

const IMAGE_EXTENSIONS: &[&str] = &["jpg", "jpeg", "png", "gif"];
const VIDEO_EXTENSIONS: &[&str] = &["mp4", "mov", "avi", "mkv"];
const MAX_SIZE: usize = 100 * 1024 * 1024; // 100mb

fn media_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("kasway-media")
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
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
    serde_json::to_value(m).unwrap_or(Value::Null)
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

    while let Some(field) = multipart.next_field().await.map_err(|_| AppError::validation_field("file", "file", "Invalid multipart payload"))? {
        match field.name().map(|s| s.to_string()).as_deref() {
            Some("file") => {
                let ext = field.file_name()
                    .and_then(|f| f.rsplit('.').next())
                    .map(|e| e.to_ascii_lowercase());
                file_ext = ext;
                // Stream chunks, rejecting early once the running size exceeds
                // MAX_SIZE so an oversized upload is never fully buffered.
                let mut field = field;
                let mut buf: Vec<u8> = Vec::new();
                while let Some(chunk) = field.chunk().await.map_err(|_| AppError::validation_field("file", "file", "Could not read uploaded file"))? {
                    if buf.len() + chunk.len() > MAX_SIZE {
                        return Err(AppError::validation_field("file", "size", "The file size must be under 100mb"));
                    }
                    buf.extend_from_slice(&chunk);
                }
                file_bytes = Some(buf);
            }
            Some("width") => width = field.text().await.ok().and_then(|t| t.trim().parse().ok()),
            Some("height") => height = field.text().await.ok().and_then(|t| t.trim().parse().ok()),
            Some("duration") => duration = field.text().await.ok().and_then(|t| t.trim().parse().ok()),
            _ => { let _ = field.bytes().await; }
        }
    }

    let bytes = file_bytes.ok_or_else(|| AppError::validation_field("file", "required", "The file field must be defined"))?;
    if bytes.len() > MAX_SIZE {
        return Err(AppError::validation_field("file", "size", "The file size must be under 100mb"));
    }
    let ext = file_ext.filter(|e| !e.is_empty())
        .filter(|e| IMAGE_EXTENSIONS.contains(&e.as_str()) || VIDEO_EXTENSIONS.contains(&e.as_str()))
        .ok_or_else(|| AppError::validation_field("file", "extname", "The file must have one of the allowed extensions"))?;

    let is_image = IMAGE_EXTENSIONS.contains(&ext.as_str());
    let media_type = if is_image { "image" } else { "video" };
    let folder = if is_image { "images" } else { "videos" };
    let key = format!("media/{folder}/{}.{ext}", uuid::Uuid::new_v4());

    // compression is best-effort (no-op here) → size stays the uploaded length
    let size = bytes.len() as i64;

    // write to the filesystem storage disk
    let path = media_dir().join(&key);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|_| AppError::commerce(500, "Storage write failed"))?;
    }
    tokio::fs::write(&path, &bytes).await.map_err(|_| AppError::commerce(500, "Storage write failed"))?;

    let now = now_iso();
    let id: i64 = sqlx::query_scalar::<_, i64>(
        "INSERT INTO media (user_id, key, media_type, status, size, width, height, duration, created_at, updated_at) \
         VALUES ($1, $2, $3, 'uploaded', $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(auth.user_id).bind(&key).bind(media_type).bind(size).bind(width).bind(height).bind(duration)
    .bind(&now).bind(&now)
    .fetch_one(&state.db.pool).await?;

    let row = sqlx::query_as::<_, MediaRow>(
        "SELECT id, user_id, key, media_type, status, size, width, height, duration, created_at, updated_at FROM media WHERE id = $1",
    ).bind(id).fetch_one(&state.db.pool).await?;
    Ok((StatusCode::CREATED, Json(serialize_media(&row))).into_response())
}

/// `DELETE /api/media/:id` (merchant)
pub async fn destroy(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Response> {
    let key: Option<String> = sqlx::query_scalar("SELECT key FROM media WHERE user_id = $1 AND id = $2")
        .bind(auth.user_id).bind(id).fetch_optional(&state.db.pool).await?;
    let Some(key) = key else {
        return Err(AppError::commerce(404, "Media not found"));
    };
    sqlx::query("DELETE FROM media WHERE id = $1").bind(id).execute(&state.db.pool).await?;
    // best-effort storage delete (@beforeDelete hook)
    let _ = tokio::fs::remove_file(media_dir().join(&key)).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}
