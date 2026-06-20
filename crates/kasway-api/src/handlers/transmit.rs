//! `/__transmit/*` — @adonisjs/transmit SSE routes (transmit.registerRoutes()).
//! events (SSE stream), subscribe, unsubscribe. Private channels
//! `merchant/:id/client/online|offline` authorize against the merchant bearer
//! (start/transmit.ts). No event producers run in the port, so the stream is a
//! keep-alive channel (pingInterval 60s, per config/transmit.ts).

use crate::auth::AuthMerchant;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::stream::{self, Stream};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::sync::Mutex;
use std::time::Duration;

static SUBSCRIPTIONS: Mutex<Option<HashMap<String, HashSet<String>>>> = Mutex::new(None);

#[derive(Deserialize)]
pub struct EventsQuery {
    #[allow(dead_code)]
    uid: Option<String>,
}

/// `GET /__transmit/events` — opens the SSE stream (keep-alive only).
pub async fn events(Query(_q): Query<EventsQuery>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
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

fn register(uid: &str, channel: &str, add: bool) {
    let mut guard = SUBSCRIPTIONS.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    let set = map.entry(uid.to_string()).or_default();
    if add { set.insert(channel.to_string()); } else { set.remove(channel); }
}

/// `POST /__transmit/subscribe`
pub async fn subscribe(reporter: Option<AuthMerchant>, Json(body): Json<Value>) -> Response {
    let uid = body.get("uid").and_then(|v| v.as_str()).unwrap_or("");
    let channel = body.get("channel").and_then(|v| v.as_str()).unwrap_or("");
    if uid.is_empty() || channel.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    // private channels require the matching merchant bearer (transmit.authorize)
    if let Some(id) = private_channel_merchant(channel) {
        match reporter {
            Some(a) if a.user_id == id => {}
            _ => return StatusCode::FORBIDDEN.into_response(),
        }
    }
    register(uid, channel, true);
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /__transmit/unsubscribe`
pub async fn unsubscribe(Json(body): Json<Value>) -> Response {
    let uid = body.get("uid").and_then(|v| v.as_str()).unwrap_or("");
    let channel = body.get("channel").and_then(|v| v.as_str()).unwrap_or("");
    if uid.is_empty() || channel.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    register(uid, channel, false);
    StatusCode::NO_CONTENT.into_response()
}
