use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;

use crate::AppState;
use crate::heartbeat::parse_pushkey_hash;

#[derive(Deserialize)]
struct HeartbeatPayload {
    pushkey_hash: String,
}

fn extract_hash(body: &Bytes) -> Result<[u8; 32], StatusCode> {
    let payload: HeartbeatPayload =
        serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    parse_pushkey_hash(&payload.pushkey_hash).map_err(|_| StatusCode::BAD_REQUEST)
}

/// `POST /heartbeat` — creates or refreshes an active-session suppression lease.
pub async fn record_heartbeat(State(state): State<AppState>, body: Bytes) -> StatusCode {
    let hash = match extract_hash(&body) {
        Ok(h) => h,
        Err(status) => return status,
    };

    match state.heartbeats.record(hash) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// `DELETE /heartbeat` and `POST /heartbeat/clear` — clears a suppression lease.
pub async fn clear_heartbeat(State(state): State<AppState>, body: Bytes) -> StatusCode {
    let hash = match extract_hash(&body) {
        Ok(h) => h,
        Err(status) => return status,
    };

    state.heartbeats.remove(&hash);
    StatusCode::NO_CONTENT
}
