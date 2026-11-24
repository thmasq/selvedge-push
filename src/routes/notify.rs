use std::collections::HashSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use tokio::task::JoinSet;

use crate::AppState;
use crate::heartbeat::hash_pushkey;
use crate::matrix::{Device, NotifyRequest, NotifyResponse, build_declarative_payload};
use crate::ssrf::ValidatedPushUrl;
use crate::webpush::crypto::{EncryptionError, encrypt_aes128gcm};
use crate::webpush::{OutboundPushRequest, PushOutcome, derive_topic};

/// Maximum length of a Matrix `room_id` or `event_id` (per Matrix spec).
const MAX_MATRIX_ID_LEN: usize = 255;

/// Maximum number of devices processed from a single `/_matrix/push/v1/notify` call.
const MAX_DEVICES_PER_NOTIFY: usize = 32;

struct ValidatedDevice {
    url: ValidatedPushUrl,
    pushkey: String,
    p256dh: String,
    auth: String,
}

enum ValidationOutcome {
    Ready(ValidatedDevice),
    Reject(String),
    Skip,
}

fn validate_device(state: &AppState, device: Device) -> ValidationOutcome {
    if device.app_id != state.config.allowed_app_id {
        return ValidationOutcome::Skip;
    }

    let Some(data) = device.data else {
        tracing::debug!("rejecting device with missing data object");
        return ValidationOutcome::Reject(device.pushkey);
    };

    let (Some(p256dh), Some(auth)) = (data.p256dh, data.auth) else {
        tracing::debug!("rejecting device with missing p256dh or auth");
        return ValidationOutcome::Reject(device.pushkey);
    };
    if p256dh.trim().is_empty() || auth.trim().is_empty() {
        tracing::debug!("rejecting device with empty p256dh or auth");
        return ValidationOutcome::Reject(device.pushkey);
    }

    let validated_url = match ValidatedPushUrl::parse(&device.pushkey) {
        Ok(url) => url,
        Err(err) => {
            tracing::warn!(reason = %err, "rejecting pushkey failing SSRF validation");
            return ValidationOutcome::Reject(device.pushkey);
        }
    };

    let pushkey_hash = hash_pushkey(&device.pushkey);
    if state.heartbeats.is_active(&pushkey_hash) {
        tracing::debug!(
            host = validated_url.host(),
            "suppressing push due to active heartbeat"
        );
        return ValidationOutcome::Skip;
    }

    ValidationOutcome::Ready(ValidatedDevice {
        url: validated_url,
        pushkey: device.pushkey,
        p256dh,
        auth,
    })
}

async fn encrypt_and_send(
    state: &AppState,
    device: ValidatedDevice,
    payload_bytes: &[u8],
    topic: &str,
) -> Option<String> {
    let encrypted = match encrypt_aes128gcm(payload_bytes, &device.p256dh, &device.auth) {
        Ok(bytes) => bytes,
        Err(EncryptionError::InvalidP256dh | EncryptionError::InvalidAuthSecret) => {
            tracing::warn!(
                host = device.url.host(),
                "rejecting device with malformed Web Push key material"
            );
            return Some(device.pushkey);
        }
        Err(err) => {
            tracing::warn!(
                host = device.url.host(),
                reason = %err,
                "skipping push due to encryption error"
            );
            return None;
        }
    };

    let authorization = match state
        .vapid
        .authorization_header(&device.url.vapid_audience(), &state.config.vapid_subject)
    {
        Ok(header) => header,
        Err(err) => {
            tracing::warn!(
                host = device.url.host(),
                reason = %err,
                "failed to sign VAPID header"
            );
            return None;
        }
    };

    let host = device.url.host().to_owned();
    let outbound = OutboundPushRequest {
        url: device.url,
        body: encrypted,
        authorization,
        ttl_secs: state.config.push_ttl_secs,
        urgency: "high",
        topic: topic.to_owned(),
    };

    match state.transport.send(outbound).await {
        PushOutcome::Delivered { status } => {
            tracing::debug!(host, status, "web push delivered");
            None
        }
        PushOutcome::SubscriptionExpired { status } => {
            tracing::info!(host, status, "web push subscription expired; rejecting");
            Some(device.pushkey)
        }
        PushOutcome::TransientFailure { status, kind } => {
            tracing::warn!(host, ?status, kind, "outbound web push failed");
            None
        }
    }
}

/// `POST /_matrix/push/v1/notify` — Matrix Push Gateway API v1.
pub async fn notify(
    State(state): State<AppState>,
    Json(req): Json<NotifyRequest>,
) -> Json<NotifyResponse> {
    let (Some(event_id), Some(room_id)) = (
        req.notification.event_id.as_deref(),
        req.notification.room_id.as_deref(),
    ) else {
        return Json(NotifyResponse {
            rejected: Vec::new(),
        });
    };

    if !room_id.starts_with('!')
        || !event_id.starts_with('$')
        || room_id.len() > MAX_MATRIX_ID_LEN
        || event_id.len() > MAX_MATRIX_ID_LEN
    {
        return Json(NotifyResponse {
            rejected: Vec::new(),
        });
    }

    let navigate = state.config.navigate_url();
    let declarative = build_declarative_payload(&navigate, room_id, event_id);
    let Ok(payload_vec) = serde_json::to_vec(&declarative) else {
        tracing::error!("failed to serialize declarative push payload");
        return Json(NotifyResponse {
            rejected: Vec::new(),
        });
    };
    let payload_bytes: Arc<[u8]> = Arc::from(payload_vec);
    let topic: Arc<str> = Arc::from(derive_topic(room_id));

    let mut rejected = Vec::new();
    let mut seen_pushkeys = HashSet::new();
    let mut in_flight = JoinSet::new();

    for device in req
        .notification
        .devices
        .into_iter()
        .take(MAX_DEVICES_PER_NOTIFY)
    {
        if !seen_pushkeys.insert(hash_pushkey(&device.pushkey)) {
            continue;
        }

        match validate_device(&state, device) {
            ValidationOutcome::Skip => {}
            ValidationOutcome::Reject(pushkey) => rejected.push(pushkey),
            ValidationOutcome::Ready(validated) => {
                let Ok(permit) = Arc::clone(&state.push_semaphore).acquire_owned().await else {
                    break;
                };

                let state = state.clone();
                let payload_bytes = Arc::clone(&payload_bytes);
                let topic = Arc::clone(&topic);

                in_flight.spawn(async move {
                    let _permit = permit;
                    encrypt_and_send(&state, validated, &payload_bytes, &topic).await
                });
            }
        }
    }

    while let Some(res) = in_flight.join_next().await {
        match res {
            Ok(Some(rejected_key)) => rejected.push(rejected_key),
            Ok(None) => {}
            Err(err) => tracing::error!(error = %err, "push dispatch task panicked"),
        }
    }

    Json(NotifyResponse { rejected })
}
