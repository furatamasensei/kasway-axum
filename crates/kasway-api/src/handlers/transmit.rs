//! `/__transmit/*` — SSE routes. `events` streams invoice state changes to a
//! watcher; `subscribe`/`unsubscribe` are the legacy @adonisjs/transmit channel
//! authorization endpoints (no registry is kept — the stream filters instead).

use crate::auth::AuthMerchant;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::stream::{self, Stream, StreamExt};
use tokio::sync::broadcast::error::RecvError;
use serde::Deserialize;
use serde_json::Value;
use std::convert::Infallible;
use std::time::Duration;

#[derive(Deserialize)]
pub struct EventsQuery {
    /// Watch one invoice. Without it the stream is keep-alive only — a client
    /// must say what it is waiting for; we do not fan every invoice out to
    /// everyone.
    invoice: Option<String>,
}

/// `GET /__transmit/events?invoice=<publicId>` — SSE stream of that invoice's
/// state changes.
///
/// The event carries no invoice data, only `{publicId, covenantState}`: it is a
/// nudge to re-read the authoritative state from the checkout endpoint. That
/// keeps the stream free of anything worth authorizing (the publicId is already
/// the capability for that endpoint), and lets it fail without breaking
/// correctness — a client that misses an event still has its slow poll.
pub async fn events(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let keep_alive = KeepAlive::new().interval(Duration::from_secs(30));
    let Some(invoice) = query.invoice else {
        return Sse::new(stream::pending().boxed()).keep_alive(keep_alive);
    };

    let body = stream::unfold(state.events.subscribe(), move |mut rx| {
        let invoice = invoice.clone();
        async move {
            loop {
                match rx.recv().await {
                    // Only this invoice's events reach the wire. Everyone else's
                    // watchers get nothing — not even a byte.
                    Ok(event) if event.public_id == invoice => {
                        let sse = Event::default()
                            .event("invoice.changed")
                            .json_data(&event)
                            .unwrap_or_default();
                        return Some((Ok(sse), rx));
                    }
                    Ok(_) => continue,
                    // Lagged = we dropped events under load. Not fatal: the client
                    // re-reads authoritative state, so a missed nudge costs nothing.
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => return None,
                }
            }
        }
    })
    .boxed();

    Sse::new(body).keep_alive(keep_alive)
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
