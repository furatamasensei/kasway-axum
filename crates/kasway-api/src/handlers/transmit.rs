//! `/__transmit/*` — @adonisjs/transmit SSE routes (transmit.registerRoutes()).
//! events (SSE stream), subscribe, unsubscribe. Private channels
//! `merchant/:id/client/online|offline` authorize against the merchant bearer
//! (start/transmit.ts). No event producers run in the port, so the stream is a
//! keep-alive channel (pingInterval 60s, per config/transmit.ts) and
//! subscribe/unsubscribe only enforce authorization — there is nothing to
//! deliver, so no subscription registry is kept.

use crate::auth::AuthMerchant;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::stream::{self, Stream};
use serde_json::Value;
use std::convert::Infallible;
use std::time::Duration;

/// `GET /__transmit/events` — opens the SSE stream (keep-alive only).
pub async fn events() -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let body = stream::pending::<Result<Event, Infallible>>();
    Sse::new(body).keep_alive(KeepAlive::new().interval(Duration::from_secs(60)))
}

/// Parse a private channel `merchant/:id/client/(online|offline)` → merchant id.
fn private_channel_merchant(channel: &str) -> Option<i64> {
    let parts: Vec<&str> = channel.split('/').collect();
    if parts.len() == 4 && parts[0] == "merchant" && parts[2] == "client" && (parts[3] == "online" || parts[3] == "offline") {
        parts[1].parse().ok()
    } else {
        None
    }
}

/// Validate the `{ uid, channel }` body shared by subscribe/unsubscribe.
fn channel_of(body: &Value) -> Option<&str> {
    let uid = body.get("uid").and_then(|v| v.as_str())?;
    let channel = body.get("channel").and_then(|v| v.as_str())?;
    (!uid.is_empty() && !channel.is_empty()).then_some(channel)
}

/// `POST /__transmit/subscribe`
pub async fn subscribe(reporter: Option<AuthMerchant>, Json(body): Json<Value>) -> Response {
    let Some(channel) = channel_of(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // private channels require the matching merchant bearer (transmit.authorize)
    if let Some(id) = private_channel_merchant(channel) {
        match reporter {
            Some(a) if a.user_id == id => {}
            _ => return StatusCode::FORBIDDEN.into_response(),
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /__transmit/unsubscribe`
pub async fn unsubscribe(Json(body): Json<Value>) -> Response {
    match channel_of(&body) {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => StatusCode::BAD_REQUEST.into_response(),
    }
}
