pub mod crypto;
pub mod vapid;

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use sha2::{Digest, Sha256};

use crate::ssrf::ValidatedPushUrl;

/// Outbound Web Push HTTP request ready to be dispatched.
#[derive(Debug, Clone)]
pub struct OutboundPushRequest {
    pub url: ValidatedPushUrl,
    pub body: Vec<u8>,
    pub authorization: String,
    pub ttl_secs: u32,
    pub urgency: &'static str,
    pub topic: String,
}

/// Outcome of an outbound Web Push HTTP delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// Push service accepted the notification (200, 201, 202).
    Delivered { status: u16 },
    /// Subscription is permanently dead (404, 410) — add `pushkey` to `rejected`.
    SubscriptionExpired { status: u16 },
    /// Temporary / non-fatal error (400, 401, 403, 429, 5xx, timeout, network error).
    TransientFailure {
        status: Option<u16>,
        kind: &'static str,
    },
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Abstraction over outbound HTTP delivery so integration tests can mock
/// push services while keeping real SSRF, encryption, and VAPID signing active.
pub trait PushTransport: Send + Sync {
    fn send(&self, request: OutboundPushRequest) -> BoxFuture<'_, PushOutcome>;
}

/// Production `reqwest`-based Web Push transport with redirects disabled and
/// a strict per-request timeout.
#[derive(Clone)]
pub struct ReqwestPushTransport {
    client: reqwest::Client,
}

impl ReqwestPushTransport {
    /// Creates a `reqwest`-based transport with HTTPS-only enforcement,
    /// redirects disabled, and `timeout`.
    ///
    /// # Errors
    /// Returns [`reqwest::Error`] if the underlying HTTP client fails to initialize.
    pub fn new(timeout: Duration) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()?;
        Ok(Self { client })
    }

    #[cfg(test)]
    fn new_allow_http_for_test(timeout: Duration) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()?;
        Ok(Self { client })
    }

    /// Low-level send helper taking an arbitrary URL string (used by `send`
    /// with `ValidatedPushUrl` and by `wiremock` tests on localhost).
    async fn send_to_url(&self, target_url: &str, request: &OutboundPushRequest) -> PushOutcome {
        let response = self
            .client
            .post(target_url)
            .header(CONTENT_ENCODING, "aes128gcm")
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(AUTHORIZATION, &request.authorization)
            .header("TTL", request.ttl_secs.to_string())
            .header("Urgency", request.urgency)
            .header("Topic", &request.topic)
            .body(request.body.clone())
            .send()
            .await;

        match response {
            Ok(resp) => classify_status(resp.status().as_u16()),
            Err(err) => {
                let kind = if err.is_timeout() {
                    "timeout"
                } else if err.is_connect() {
                    "connect"
                } else if err.is_redirect() {
                    "redirect"
                } else {
                    "network"
                };
                PushOutcome::TransientFailure { status: None, kind }
            }
        }
    }
}

impl PushTransport for ReqwestPushTransport {
    fn send(&self, request: OutboundPushRequest) -> BoxFuture<'_, PushOutcome> {
        Box::pin(async move { self.send_to_url(request.url.as_str(), &request).await })
    }
}

#[must_use]
pub const fn classify_status(status: u16) -> PushOutcome {
    match status {
        200..=202 => PushOutcome::Delivered { status },
        404 | 410 => PushOutcome::SubscriptionExpired { status },
        _ => PushOutcome::TransientFailure {
            status: Some(status),
            kind: "http_status",
        },
    }
}

/// Derives the RFC 8030 `Topic` header from a Matrix `room_id`:
/// first 32 characters of `base64url_nopad(sha256(room_id))`.
#[must_use]
pub fn derive_topic(room_id: &str) -> String {
    let digest = Sha256::digest(room_id.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(digest);
    encoded[..32].to_owned()
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn topic_is_32_url_safe_chars_and_deterministic() {
        let t1 = derive_topic("!room123:example.org");
        let t2 = derive_topic("!room123:example.org");
        let t3 = derive_topic("!other:example.org");

        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
        assert_eq!(t1.len(), 32);
        assert!(
            t1.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }

    #[tokio::test]
    async fn reqwest_transport_disables_redirects_and_sends_headers() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/push"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/redirect"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/push", server.uri())),
            )
            .mount(&server)
            .await;

        let transport =
            ReqwestPushTransport::new_allow_http_for_test(Duration::from_secs(2)).unwrap();
        let req = OutboundPushRequest {
            url: ValidatedPushUrl::parse("https://fcm.googleapis.com/fcm/send/x").unwrap(),
            body: b"ciphertext".to_vec(),
            authorization: "vapid t=abc, k=def".into(),
            ttl_secs: 86_400,
            urgency: "high",
            topic: "test-topic".into(),
        };

        let ok = transport
            .send_to_url(&format!("{}/push", server.uri()), &req)
            .await;
        assert_eq!(ok, PushOutcome::Delivered { status: 201 });

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let h = &received[0].headers;
        assert_eq!(h.get("content-encoding").unwrap(), "aes128gcm");
        assert_eq!(h.get("content-type").unwrap(), "application/octet-stream");
        assert_eq!(h.get("ttl").unwrap(), "86400");
        assert_eq!(h.get("urgency").unwrap(), "high");
        assert_eq!(h.get("topic").unwrap(), "test-topic");
        assert_eq!(h.get("authorization").unwrap(), "vapid t=abc, k=def");
        assert_eq!(received[0].body, b"ciphertext");

        // 302 must NOT be followed; treated as non-fatal transient failure
        let redir = transport
            .send_to_url(&format!("{}/redirect", server.uri()), &req)
            .await;
        assert_eq!(
            redir,
            PushOutcome::TransientFailure {
                status: Some(302),
                kind: "http_status",
            }
        );

        // Production transport must refuse plain HTTP URLs
        let prod_transport = ReqwestPushTransport::new(Duration::from_secs(2)).unwrap();
        let http_refused = prod_transport
            .send_to_url(&format!("{}/push", server.uri()), &req)
            .await;
        assert!(matches!(
            http_refused,
            PushOutcome::TransientFailure { status: None, .. }
        ));
    }
}
