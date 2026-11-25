use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use tokio::task::JoinSet;

use crate::AppState;
use crate::debounce::{DebounceKey, EnqueueResult, PendingDevice, PollBatch};
use crate::heartbeat::hash_pushkey;
use crate::matrix::{
    Device, NotifyRequest, NotifyResponse, QuietHours, build_coalesced_declarative_payload,
    build_declarative_payload,
};
use crate::ssrf::ValidatedPushUrl;
use crate::webpush::crypto::{EncryptionError, encrypt_aes128gcm};
use crate::webpush::{OutboundPushRequest, PushOutcome, derive_topic};

/// Maximum length of a Matrix `room_id` or `event_id` (per Matrix spec).
const MAX_MATRIX_ID_LEN: usize = 255;

/// Maximum number of devices processed from a single `/_matrix/push/v1/notify` call.
const MAX_DEVICES_PER_NOTIFY: usize = 32;

struct ValidatedDevice {
    pending: PendingDevice,
    debounce_window: Duration,
    bypass_debounce_on_highlight: bool,
    is_highlight: bool,
}

impl ValidatedDevice {
    const fn should_debounce(&self) -> bool {
        if self.debounce_window.is_zero() {
            return false;
        }
        !(self.is_highlight && self.bypass_debounce_on_highlight)
    }
}

enum ValidationOutcome {
    Ready(Box<ValidatedDevice>),
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

    if state.debounce.is_rejected(&pushkey_hash) {
        tracing::info!(
            host = validated_url.host(),
            "rejecting pushkey cached as expired from prior background flush"
        );
        return ValidationOutcome::Reject(device.pushkey);
    }

    if state.heartbeats.is_active(&pushkey_hash) {
        tracing::debug!(
            host = validated_url.host(),
            "suppressing push due to active heartbeat"
        );
        return ValidationOutcome::Skip;
    }

    let quiet_hours = data.quiet_hours.filter(|qh| qh.is_valid());
    if quiet_hours.is_some_and(QuietHours::is_active_now) {
        tracing::debug!(
            host = validated_url.host(),
            "suppressing push due to quiet hours"
        );
        return ValidationOutcome::Skip;
    }

    let debounce_window = Duration::from_millis(data.debounce_ms.unwrap_or(0));
    let is_highlight = device.tweaks.and_then(|t| t.highlight).unwrap_or(false);

    ValidationOutcome::Ready(Box::new(ValidatedDevice {
        pending: PendingDevice {
            url: validated_url,
            pushkey: device.pushkey,
            pushkey_hash,
            p256dh,
            auth,
            quiet_hours,
        },
        debounce_window,
        bypass_debounce_on_highlight: data.bypass_debounce_on_highlight,
        is_highlight,
    }))
}

async fn encrypt_and_send(
    state: &AppState,
    device: PendingDevice,
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

fn spawn_debounce_flusher(state: AppState, key: DebounceKey, batch_id: u64, topic: Arc<str>) {
    tokio::spawn(async move {
        let batch = loop {
            match state.debounce.poll_ready(&key, batch_id) {
                PollBatch::SleepUntil(deadline) => tokio::time::sleep_until(deadline).await,
                PollBatch::Ready(batch) => break *batch,
                PollBatch::Gone => return,
            }
        };

        let pushkey_hash = batch.device.pushkey_hash;

        if state.heartbeats.is_active(&pushkey_hash) {
            tracing::debug!(
                host = batch.device.url.host(),
                count = batch.count,
                "dropping debounced batch due to active heartbeat at flush time"
            );
            return;
        }

        if batch
            .device
            .quiet_hours
            .is_some_and(QuietHours::is_active_now)
        {
            tracing::debug!(
                host = batch.device.url.host(),
                count = batch.count,
                "dropping debounced batch due to quiet hours at flush time"
            );
            return;
        }

        let navigate = state.config.navigate_url();
        let declarative = build_coalesced_declarative_payload(
            &navigate,
            &batch.room_id,
            &batch.latest_event_id,
            batch.count,
        );
        let Ok(payload_bytes) = serde_json::to_vec(&declarative) else {
            tracing::error!("failed to serialize coalesced declarative push payload");
            return;
        };

        let Ok(permit) = Arc::clone(&state.push_semaphore).acquire_owned().await else {
            return;
        };
        let _permit = permit;

        if encrypt_and_send(&state, batch.device, &payload_bytes, &topic)
            .await
            .is_some()
        {
            state.debounce.record_rejected(pushkey_hash);
        }
    });
}

fn handle_unread_reset(state: &AppState, notification: crate::matrix::Notification) {
    let is_unread_reset = notification.counts.as_ref().and_then(|c| c.unread) == Some(0);
    if !is_unread_reset {
        return;
    }

    let valid_room = notification
        .room_id
        .as_deref()
        .filter(|rid| rid.starts_with('!') && rid.len() <= MAX_MATRIX_ID_LEN);

    let mut seen = HashSet::new();
    for device in notification
        .devices
        .into_iter()
        .take(MAX_DEVICES_PER_NOTIFY)
    {
        if device.app_id != state.config.allowed_app_id {
            continue;
        }
        let pushkey_hash = hash_pushkey(&device.pushkey);
        if !seen.insert(pushkey_hash) {
            continue;
        }
        if let Some(rid) = valid_room {
            let _ = state.debounce.take_pending(&(pushkey_hash, rid.to_owned()));
        } else {
            let _ = state.debounce.clear_device_pending(&pushkey_hash);
        }
    }
}

fn resolve_immediate_payload(
    state: &AppState,
    key: &DebounceKey,
    navigate: &str,
    room_id: &str,
    event_id: &str,
    single_payload_bytes: &Arc<[u8]>,
) -> Option<Arc<[u8]>> {
    let pending_count = state
        .debounce
        .take_pending(key)
        .map_or(0, |existing| existing.count);
    let total_count = pending_count.saturating_add(1);

    if total_count <= 1 {
        return Some(Arc::clone(single_payload_bytes));
    }

    let coalesced = build_coalesced_declarative_payload(navigate, room_id, event_id, total_count);
    serde_json::to_vec(&coalesced).map_or_else(
        |_| {
            tracing::error!("failed to serialize coalesced declarative push payload");
            None
        },
        |vec| Some(Arc::from(vec)),
    )
}

fn try_enqueue_debounce(
    state: &AppState,
    validated: &ValidatedDevice,
    key: DebounceKey,
    room_id: &str,
    event_id: &str,
    topic: &Arc<str>,
) -> bool {
    if !validated.should_debounce() {
        return false;
    }

    match state.debounce.enqueue(
        validated.pending.clone(),
        room_id.to_owned(),
        event_id.to_owned(),
        validated.debounce_window,
    ) {
        EnqueueResult::SpawnFlusher { batch_id } => {
            spawn_debounce_flusher(state.clone(), key, batch_id, Arc::clone(topic));
            true
        }
        EnqueueResult::Updated => true,
        EnqueueResult::AtCapacity => {
            tracing::warn!(
                host = validated.pending.url.host(),
                "debounce store at capacity; falling back to immediate send"
            );
            false
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
        handle_unread_reset(&state, req.notification);
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
    let single_payload_bytes: Arc<[u8]> = Arc::from(payload_vec);
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
                let key: DebounceKey = (validated.pending.pushkey_hash, room_id.to_owned());
                if try_enqueue_debounce(&state, &validated, key.clone(), room_id, event_id, &topic)
                {
                    continue;
                }

                let Some(payload_bytes) = resolve_immediate_payload(
                    &state,
                    &key,
                    &navigate,
                    room_id,
                    event_id,
                    &single_payload_bytes,
                ) else {
                    continue;
                };

                let Ok(permit) = Arc::clone(&state.push_semaphore).acquire_owned().await else {
                    break;
                };

                let state = state.clone();
                let topic = Arc::clone(&topic);
                let pending = validated.pending;

                in_flight.spawn(async move {
                    let _permit = permit;
                    encrypt_and_send(&state, pending, &payload_bytes, &topic).await
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
