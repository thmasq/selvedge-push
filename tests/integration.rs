use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use http_body_util::BodyExt;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use selvedge_push::AppState;
use selvedge_push::config::Config;
use selvedge_push::heartbeat::{HeartbeatStore, hash_pushkey};
use selvedge_push::matrix::NotifyResponse;
use selvedge_push::routes::build_router;
use selvedge_push::webpush::vapid::{VapidKey, generate_vapid_keypair};
use selvedge_push::webpush::{
    BoxFuture, OutboundPushRequest, PushOutcome, PushTransport, derive_topic,
};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::sync::Semaphore;
use tower::ServiceExt;

/// Mock transport that records every outbound request and returns configurable
/// per-URL outcomes (defaulting to `201 Created`).
#[derive(Default)]
struct MockTransport {
    sent: Mutex<Vec<OutboundPushRequest>>,
    outcomes: Mutex<HashMap<String, PushOutcome>>,
}

impl MockTransport {
    fn set_outcome(&self, pushkey: &str, outcome: PushOutcome) {
        self.outcomes
            .lock()
            .unwrap()
            .insert(pushkey.to_owned(), outcome);
    }

    fn take_sent(&self) -> Vec<OutboundPushRequest> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }
}

impl PushTransport for MockTransport {
    fn send(&self, request: OutboundPushRequest) -> BoxFuture<'_, PushOutcome> {
        let outcome = self
            .outcomes
            .lock()
            .unwrap()
            .get(request.url.as_str())
            .cloned()
            .unwrap_or(PushOutcome::Delivered { status: 201 });
        self.sent.lock().unwrap().push(request);
        Box::pin(async move { outcome })
    }
}

struct TestSubscriber {
    ua_private: SecretKey,
    p256dh_b64: String,
    auth: [u8; 16],
    auth_b64: String,
}

impl TestSubscriber {
    fn generate() -> Self {
        let mut raw = [0u8; 32];
        let ua_private = loop {
            getrandom::fill(&mut raw).unwrap();
            if let Ok(k) = SecretKey::from_slice(&raw) {
                break k;
            }
        };
        let p256dh_b64 = URL_SAFE_NO_PAD.encode(ua_private.public_key().to_sec1_point(false));
        let mut auth = [0u8; 16];
        getrandom::fill(&mut auth).unwrap();
        let auth_b64 = URL_SAFE_NO_PAD.encode(auth);
        Self {
            ua_private,
            p256dh_b64,
            auth,
            auth_b64,
        }
    }

    fn decrypt(&self, body: &[u8]) -> Value {
        let salt = &body[0..16];
        let idlen = body[20] as usize;
        let as_pub_bytes = &body[21..21 + idlen];
        let ciphertext = &body[21 + idlen..];

        let as_public = PublicKey::from_sec1_bytes(as_pub_bytes).unwrap();
        let ua_pub_point = self.ua_private.public_key().to_sec1_point(false);

        let shared =
            p256::ecdh::diffie_hellman(self.ua_private.to_nonzero_scalar(), as_public.as_affine());

        let mut key_info = Vec::new();
        key_info.extend_from_slice(b"WebPush: info\0");
        key_info.extend_from_slice(ua_pub_point.as_bytes());
        key_info.extend_from_slice(as_pub_bytes);

        let hkdf_auth = Hkdf::<Sha256>::new(Some(&self.auth), shared.raw_secret_bytes());
        let mut ikm = [0u8; 32];
        hkdf_auth.expand(&key_info, &mut ikm).unwrap();

        let hkdf_content = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut cek = [0u8; 16];
        hkdf_content
            .expand(b"Content-Encoding: aes128gcm\0", &mut cek)
            .unwrap();
        let mut nonce = [0u8; 12];
        hkdf_content
            .expand(b"Content-Encoding: nonce\0", &mut nonce)
            .unwrap();

        let cipher = Aes128Gcm::new_from_slice(&cek).unwrap();
        let mut plaintext = cipher.decrypt(&Nonce::from(nonce), ciphertext).unwrap();
        assert_eq!(plaintext.pop(), Some(0x02));
        serde_json::from_slice(&plaintext).unwrap()
    }
}

fn build_test_app() -> (Router, Arc<MockTransport>) {
    let keys = generate_vapid_keypair().unwrap();
    let env = HashMap::from([
        (
            "VAPID_PRIVATE_KEY",
            keys.private_key_b64.as_str().to_owned(),
        ),
        ("VAPID_SUBJECT", "mailto:admin@example.com".to_owned()),
        ("APP_BASE_URL", "https://selvedge.example.com".to_owned()),
    ]);
    let (config, vapid_private_key) = Config::from_lookup(|k| env.get(k).cloned()).unwrap();
    let config = Arc::new(config);
    let vapid = Arc::new(VapidKey::parse(vapid_private_key.expose()).unwrap());

    drop(vapid_private_key);

    let heartbeats = Arc::new(HeartbeatStore::new(
        config.heartbeat_ttl,
        config.max_heartbeats,
    ));
    let transport = Arc::new(MockTransport::default());

    let state = AppState {
        push_semaphore: Arc::new(Semaphore::new(config.max_concurrent_pushes)),
        config,
        vapid,
        heartbeats,
        transport: transport.clone(),
    };

    (build_router(state), transport)
}

async fn post_json(app: &Router, uri: &str, body: Value) -> (StatusCode, Vec<u8>) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}

fn notify_body(room_id: Option<&str>, event_id: Option<&str>, devices: Vec<Value>) -> Value {
    json!({
        "notification": {
            "event_id": event_id,
            "room_id": room_id,
            "devices": devices
        }
    })
}

fn device_json(pushkey: &str, sub: &TestSubscriber) -> Value {
    json!({
        "app_id": "org.selvedge.web",
        "pushkey": pushkey,
        "data": {
            "url": "https://push.example.com/_matrix/push/v1/notify",
        "format": "event_id_only",
            "p256dh": sub.p256dh_b64,
            "auth": sub.auth_b64
        }
    })
}

#[tokio::test]
async fn health_and_body_size_limit() {
    let (app, _) = build_test_app();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body, json!({"status": "ok"}));

    // > 16 KiB body must be rejected with 413 Payload Too Large
    let oversized = vec![b'a'; 16 * 1024 + 1];
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/_matrix/push/v1/notify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(oversized))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn declarative_payload_and_topic_header_end_to_end() {
    let (app, transport) = build_test_app();
    let sub = TestSubscriber::generate();
    let pushkey = "https://fcm.googleapis.com/fcm/send/device-token-1";

    let (status, body) = post_json(
        &app,
        "/_matrix/push/v1/notify",
        notify_body(
            Some("!room123:example.org"),
            Some("$event123"),
            vec![device_json(pushkey, &sub)],
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let resp: NotifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(resp.rejected.is_empty());

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let req = &sent[0];
    assert_eq!(req.url.as_str(), pushkey);
    assert_eq!(req.ttl_secs, 86_400);
    assert_eq!(req.urgency, "high");
    assert_eq!(req.topic, derive_topic("!room123:example.org"));
    assert!(req.topic.len() <= 32);
    assert!(req.authorization.starts_with("vapid t="));

    let decrypted = sub.decrypt(&req.body);
    assert_eq!(decrypted["web_push"], 8030);
    assert_eq!(decrypted["notification"]["title"], "Selvedge");
    assert_eq!(decrypted["notification"]["body"], "New message");
    assert_eq!(
        decrypted["notification"]["navigate"],
        "https://selvedge.example.com/"
    );
    assert_eq!(decrypted["notification"]["mutable"], true);
    assert_eq!(decrypted["notification"]["tag"], "$event123");
    assert_eq!(
        decrypted["notification"]["data"]["room_id"],
        "!room123:example.org"
    );
    assert_eq!(decrypted["notification"]["data"]["event_id"], "$event123");
}

#[tokio::test]
async fn unread_reset_and_invalid_matrix_ids_do_not_push() {
    let (app, transport) = build_test_app();
    let sub = TestSubscriber::generate();
    let pushkey = "https://web.push.apple.com/Q123";

    for (room_id, event_id) in [
        (Some("!room:example.org"), None),
        (None, Some("$event")),
        (None, None),
        (Some("not-a-room"), Some("$event")),
        (Some("!room:example.org"), Some("not-an-event")),
    ] {
        let (status, body) = post_json(
            &app,
            "/_matrix/push/v1/notify",
            notify_body(room_id, event_id, vec![device_json(pushkey, &sub)]),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resp: NotifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(resp.rejected.is_empty());
    }

    assert!(transport.take_sent().is_empty());
}

#[tokio::test]
async fn ssrf_invalid_pushkeys_are_rejected_without_network_call() {
    let (app, transport) = build_test_app();
    let sub = TestSubscriber::generate();

    let bad_urls = [
        "http://fcm.googleapis.com/fcm/send/a",
        "https://127.0.0.1/push",
        "https://[::1]/push",
        "https://fcm.googleapis.com:8443/fcm/send/a",
        "https://evil.com/push",
        "https://fcm.googleapis.com.evil.com/push",
    ];
    let devices: Vec<Value> = bad_urls.iter().map(|u| device_json(u, &sub)).collect();

    let (status, body) = post_json(
        &app,
        "/_matrix/push/v1/notify",
        notify_body(Some("!r:example.org"), Some("$e1"), devices),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let resp: NotifyResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.rejected.len(), bad_urls.len());
    for u in bad_urls {
        assert!(resp.rejected.contains(&u.to_owned()));
    }
    assert!(transport.take_sent().is_empty());
}

#[tokio::test]
async fn dead_subscriptions_rejected_and_transient_errors_preserved() {
    let (app, transport) = build_test_app();
    let sub = TestSubscriber::generate();

    let url_404 = "https://fcm.googleapis.com/fcm/send/dead404";
    let url_410 = "https://push.services.mozilla.com/wpush/v2/dead410";
    let url_500 = "https://web.push.apple.com/transient500";
    let url_429 = "https://wns2.notify.windows.com/w/?token=transient429";
    let url_other_app = "https://fcm.googleapis.com/fcm/send/other-app";

    transport.set_outcome(url_404, PushOutcome::SubscriptionExpired { status: 404 });
    transport.set_outcome(url_410, PushOutcome::SubscriptionExpired { status: 410 });
    transport.set_outcome(
        url_500,
        PushOutcome::TransientFailure {
            status: Some(500),
            kind: "http_status",
        },
    );
    transport.set_outcome(
        url_429,
        PushOutcome::TransientFailure {
            status: Some(429),
            kind: "http_status",
        },
    );

    let mut other_app_device = device_json(url_other_app, &sub);
    other_app_device["app_id"] = json!("im.vector.app");

    let (status, body) = post_json(
        &app,
        "/_matrix/push/v1/notify",
        notify_body(
            Some("!r:example.org"),
            Some("$e1"),
            vec![
                device_json(url_404, &sub),
                device_json(url_410, &sub),
                device_json(url_500, &sub),
                device_json(url_429, &sub),
                other_app_device,
            ],
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let resp: NotifyResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.rejected.len(), 2);
    assert!(resp.rejected.contains(&url_404.to_owned()));
    assert!(resp.rejected.contains(&url_410.to_owned()));
    // 4 matching-app devices sent; other_app skipped
    assert_eq!(transport.take_sent().len(), 4);
}

#[tokio::test(start_paused = true)]
async fn heartbeat_suppresses_and_clear_or_expiry_reenables() {
    let (app, transport) = build_test_app();
    let sub = TestSubscriber::generate();
    let pushkey = "https://fcm.googleapis.com/fcm/send/active-tab";
    let pushkey_hash = hex::encode(hash_pushkey(pushkey));

    // 1. Invalid hash returns 400
    let (status, _) = post_json(&app, "/heartbeat", json!({"pushkey_hash": "bad"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // 2. Record heartbeat -> 204
    let (status, _) = post_json(&app, "/heartbeat", json!({"pushkey_hash": pushkey_hash})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // 3. Notify is suppressed without rejecting
    let (status, body) = post_json(
        &app,
        "/_matrix/push/v1/notify",
        notify_body(
            Some("!r:example.org"),
            Some("$e1"),
            vec![device_json(pushkey, &sub)],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp: NotifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(resp.rejected.is_empty());
    assert!(transport.take_sent().is_empty());

    // 4. POST /heartbeat/clear with text/plain (navigator.sendBeacon) re-enables push
    let beacon_req = Request::builder()
        .method(Method::POST)
        .uri("/heartbeat/clear")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(
            serde_json::to_vec(&json!({"pushkey_hash": pushkey_hash})).unwrap(),
        ))
        .unwrap();
    let beacon_resp = app.clone().oneshot(beacon_req).await.unwrap();
    assert_eq!(beacon_resp.status(), StatusCode::NO_CONTENT);

    let (status, _) = post_json(
        &app,
        "/_matrix/push/v1/notify",
        notify_body(
            Some("!r:example.org"),
            Some("$e2"),
            vec![device_json(pushkey, &sub)],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(transport.take_sent().len(), 1);

    // 5. Re-record heartbeat, advance past 90s TTL -> push re-enabled automatically
    let (status, _) = post_json(&app, "/heartbeat", json!({"pushkey_hash": pushkey_hash})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    tokio::time::advance(Duration::from_secs(91)).await;

    let (status, _) = post_json(
        &app,
        "/_matrix/push/v1/notify",
        notify_body(
            Some("!r:example.org"),
            Some("$e3"),
            vec![device_json(pushkey, &sub)],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(transport.take_sent().len(), 1);
}

#[tokio::test]
async fn cors_enabled_on_heartbeat_and_absent_on_notify() {
    let (app, _) = build_test_app();

    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri("/heartbeat")
        .header(header::ORIGIN, "https://selvedge.example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(preflight).await.unwrap();
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://selvedge.example.com"
    );

    let notify_req = Request::builder()
        .method(Method::POST)
        .uri("/_matrix/push/v1/notify")
        .header(header::ORIGIN, "https://selvedge.example.com")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&notify_body(None, None, vec![])).unwrap(),
        ))
        .unwrap();
    let resp = app.oneshot(notify_req).await.unwrap();
    assert!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
}
