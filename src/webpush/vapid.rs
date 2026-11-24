use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::SecretKey;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::DecodePrivateKey;
use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroizing;

/// VAPID JWT lifetime (12 hours; RFC 8292 allows up to 24 hours).
const VAPID_EXPIRY_SECS: u64 = 12 * 60 * 60;

#[derive(Debug, Error)]
pub enum VapidError {
    #[error("failed to generate random key material")]
    RngFailed,

    #[error("invalid VAPID private key format")]
    InvalidPrivateKey,

    #[error("system clock error")]
    ClockError,

    #[error("failed to serialize VAPID JWT claims")]
    SerializationFailed,
}

/// Generated VAPID keypair ready to be printed for configuration.
pub struct GeneratedVapidKeys {
    pub private_key_b64: Zeroizing<String>,
    pub public_key_b64: String,
}

/// Loaded VAPID P-256 signing key and pre-encoded uncompressed public key.
pub struct VapidKey {
    signing_key: SigningKey,
    public_key_b64: String,
}

impl fmt::Debug for VapidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VapidKey")
            .field("signing_key", &"[REDACTED]")
            .field("public_key_b64", &self.public_key_b64)
            .finish()
    }
}

#[derive(Serialize)]
struct JwtHeader {
    typ: &'static str,
    alg: &'static str,
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    aud: &'a str,
    exp: u64,
    sub: &'a str,
}

/// Generates a fresh P-256 `SecretKey` using OS randomness.
pub(crate) fn generate_p256_secret_key() -> Result<SecretKey, VapidError> {
    let mut raw = Zeroizing::new([0u8; 32]);
    loop {
        getrandom::fill(&mut *raw).map_err(|_| VapidError::RngFailed)?;
        if let Ok(key) = SecretKey::from_slice(&*raw) {
            return Ok(key);
        }
    }
}

/// Generates a fresh VAPID keypair (base64url raw 32-byte private key and
/// 65-byte uncompressed public key).
///
/// # Errors
/// Returns [`VapidError::RngFailed`] if the OS CSPRNG fails.
pub fn generate_vapid_keypair() -> Result<GeneratedVapidKeys, VapidError> {
    let secret = generate_p256_secret_key()?;
    let raw_private = Zeroizing::new(secret.to_bytes());
    let private_key_b64 = Zeroizing::new(URL_SAFE_NO_PAD.encode(*raw_private));
    let public_key_b64 = encode_uncompressed_public_key(&secret);

    Ok(GeneratedVapidKeys {
        private_key_b64,
        public_key_b64,
    })
}

fn encode_uncompressed_public_key(secret: &SecretKey) -> String {
    let point = secret.public_key().to_sec1_point(false);
    URL_SAFE_NO_PAD.encode(point.as_bytes())
}

impl VapidKey {
    /// Parses a VAPID P-256 private key from either PEM (PKCS#8 or SEC1) or
    /// base64url-encoded raw 32-byte scalar.
    ///
    /// # Errors
    /// Returns [`VapidError::InvalidPrivateKey`] if `raw` is not a valid P-256 private key.
    pub fn parse(raw: &str) -> Result<Self, VapidError> {
        let trimmed = raw.trim();
        let secret = if trimmed.starts_with("-----BEGIN") {
            SecretKey::from_pkcs8_pem(trimmed)
                .or_else(|_| SecretKey::from_sec1_pem(trimmed))
                .map_err(|_| VapidError::InvalidPrivateKey)?
        } else {
            let unpadded = trimmed.trim_end_matches('=');
            let decoded = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(unpadded)
                    .map_err(|_| VapidError::InvalidPrivateKey)?,
            );
            if decoded.len() != 32 {
                return Err(VapidError::InvalidPrivateKey);
            }
            SecretKey::from_slice(&decoded).map_err(|_| VapidError::InvalidPrivateKey)?
        };

        let public_key_b64 = encode_uncompressed_public_key(&secret);
        let signing_key = SigningKey::from(&secret);

        Ok(Self {
            signing_key,
            public_key_b64,
        })
    }

    #[must_use]
    pub fn public_key_b64(&self) -> &str {
        &self.public_key_b64
    }

    /// Builds the RFC 8292 `Authorization: vapid t=<jwt>, k=<pub>` header value.
    ///
    /// # Errors
    /// Returns [`VapidError`] if the system clock is before the Unix epoch or JWT
    /// serialization fails.
    pub fn authorization_header(
        &self,
        audience: &str,
        subject: &str,
    ) -> Result<String, VapidError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VapidError::ClockError)?
            .as_secs();

        let header = JwtHeader {
            typ: "JWT",
            alg: "ES256",
        };
        let claims = JwtClaims {
            aud: audience,
            exp: now.saturating_add(VAPID_EXPIRY_SECS),
            sub: subject,
        };

        let header_json =
            serde_json::to_vec(&header).map_err(|_| VapidError::SerializationFailed)?;
        let claims_json =
            serde_json::to_vec(&claims).map_err(|_| VapidError::SerializationFailed)?;

        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&header_json),
            URL_SAFE_NO_PAD.encode(&claims_json)
        );

        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!(
            "vapid t={signing_input}.{sig_b64}, k={}",
            self.public_key_b64
        ))
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::EncodePrivateKey;

    use super::*;

    #[test]
    fn generates_parses_and_signs_valid_vapid_jwt() {
        let generated = generate_vapid_keypair().unwrap();
        let pub_bytes = URL_SAFE_NO_PAD.decode(&generated.public_key_b64).unwrap();
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04);

        let vapid = VapidKey::parse(&generated.private_key_b64).unwrap();
        assert_eq!(vapid.public_key_b64(), generated.public_key_b64);

        let auth = vapid
            .authorization_header("https://fcm.googleapis.com", "mailto:admin@example.com")
            .unwrap();
        assert!(auth.starts_with("vapid t="));

        let (jwt_part, k_part) = auth
            .strip_prefix("vapid t=")
            .unwrap()
            .split_once(", k=")
            .unwrap();
        assert_eq!(k_part, generated.public_key_b64);

        let parts: Vec<&str> = jwt_part.split('.').collect();
        assert_eq!(parts.len(), 3);

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(sig_bytes.len(), 64);

        let verifying_key = VerifyingKey::from_sec1_bytes(&pub_bytes).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        verifying_key
            .verify(signing_input.as_bytes(), &sig)
            .expect("VAPID JWT signature must verify");
    }

    #[test]
    fn parses_pkcs8_pem_private_key() {
        let secret = generate_p256_secret_key().unwrap();
        let pem = secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("PEM encode");
        let vapid = VapidKey::parse(pem.as_str()).unwrap();
        assert_eq!(
            vapid.public_key_b64(),
            encode_uncompressed_public_key(&secret)
        );
    }

    #[test]
    fn debug_redacts_private_key() {
        let generated = generate_vapid_keypair().unwrap();
        let vapid = VapidKey::parse(&generated.private_key_b64).unwrap();
        let dbg = format!("{vapid:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(generated.private_key_b64.as_str()));
    }
}
