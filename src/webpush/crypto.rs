use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::webpush::vapid::generate_p256_secret_key;

/// RFC 8188 record size (4096 bytes).
const RECORD_SIZE: u32 = 4096;
/// RFC 8188 final-record padding delimiter.
const FINAL_RECORD_DELIMITER: u8 = 0x02;
/// Uncompressed P-256 public key length (`0x04 || X || Y`).
const UNCOMPRESSED_PUBKEY_IDLEN: u8 = 65;
const UNCOMPRESSED_PUBKEY_LEN: usize = UNCOMPRESSED_PUBKEY_IDLEN as usize;
/// RFC 8291 auth secret length.
const AUTH_SECRET_LEN: usize = 16;
/// RFC 8188 salt length.
const SALT_LEN: usize = 16;
/// AES-128-GCM authentication tag length.
const GCM_TAG_LEN: usize = 16;
/// RFC 8188 header length: salt (16) + rs (4) + idlen (1) + keyid (65).
const HEADER_LEN: usize = SALT_LEN + 4 + 1 + UNCOMPRESSED_PUBKEY_LEN;
/// Maximum plaintext length so the entire encrypted body (header + ciphertext)
/// fits within the 4096-byte Web Push payload limit.
pub const MAX_PLAINTEXT_LEN: usize = RECORD_SIZE as usize - HEADER_LEN - 1 - GCM_TAG_LEN;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("invalid p256dh client public key")]
    InvalidP256dh,

    #[error("invalid auth secret")]
    InvalidAuthSecret,

    #[error("failed to generate random bytes")]
    RngFailed,

    #[error("payload exceeds maximum Web Push size")]
    PayloadTooLarge,

    #[error("AEAD encryption failed")]
    EncryptFailed,
}

/// Encrypts `plaintext` using RFC 8291 (`aes128gcm`) for a subscriber's
/// base64url-encoded `p256dh` public key and `auth` secret.
///
/// # Errors
/// Returns [`EncryptionError`] if key material is invalid, randomness fails,
/// the payload exceeds the Web Push record size, or AEAD encryption fails.
pub fn encrypt_aes128gcm(
    plaintext: &[u8],
    p256dh_b64: &str,
    auth_b64: &str,
) -> Result<Vec<u8>, EncryptionError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(EncryptionError::PayloadTooLarge);
    }

    let ua_public_bytes = URL_SAFE_NO_PAD
        .decode(p256dh_b64.trim().trim_end_matches('='))
        .map_err(|_| EncryptionError::InvalidP256dh)?;
    if ua_public_bytes.len() != UNCOMPRESSED_PUBKEY_LEN {
        return Err(EncryptionError::InvalidP256dh);
    }
    let ua_public =
        PublicKey::from_sec1_bytes(&ua_public_bytes).map_err(|_| EncryptionError::InvalidP256dh)?;

    let auth_bytes = URL_SAFE_NO_PAD
        .decode(auth_b64.trim().trim_end_matches('='))
        .map_err(|_| EncryptionError::InvalidAuthSecret)?;
    if auth_bytes.len() != AUTH_SECRET_LEN {
        return Err(EncryptionError::InvalidAuthSecret);
    }

    let as_private = generate_p256_secret_key().map_err(|_| EncryptionError::RngFailed)?;
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| EncryptionError::RngFailed)?;

    encrypt_with_params(plaintext, &ua_public, &auth_bytes, &as_private, &salt)
}

fn encrypt_with_params(
    plaintext: &[u8],
    ua_public: &PublicKey,
    auth_secret: &[u8],
    as_private: &SecretKey,
    salt: &[u8; SALT_LEN],
) -> Result<Vec<u8>, EncryptionError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(EncryptionError::PayloadTooLarge);
    }

    // ECDH shared secret
    let shared_secret =
        p256::ecdh::diffie_hellman(as_private.to_nonzero_scalar(), ua_public.as_affine());

    let ua_pub_point = ua_public.to_sec1_point(false);
    let ua_pub_bytes = ua_pub_point.as_bytes();
    let as_pub_point = as_private.public_key().to_sec1_point(false);
    let as_pub_bytes = as_pub_point.as_bytes();

    // IKM = HKDF-SHA-256(salt = auth_secret, ikm = ecdh_secret, info = "WebPush: info\0" || ua_pub || as_pub)
    let mut key_info = Vec::with_capacity(14 + UNCOMPRESSED_PUBKEY_LEN * 2);
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(ua_pub_bytes);
    key_info.extend_from_slice(as_pub_bytes);

    let hkdf_auth = Hkdf::<Sha256>::new(Some(auth_secret), shared_secret.raw_secret_bytes());
    let mut ikm = Zeroizing::new([0u8; 32]);
    hkdf_auth
        .expand(&key_info, &mut *ikm)
        .expect("32-byte HKDF output is valid");

    // CEK (16 bytes) & Nonce (12 bytes)
    let hkdf_content = Hkdf::<Sha256>::new(Some(salt), &*ikm);
    let mut cek = Zeroizing::new([0u8; 16]);
    hkdf_content
        .expand(b"Content-Encoding: aes128gcm\0", &mut *cek)
        .expect("16-byte HKDF output is valid");

    let mut nonce_bytes = Zeroizing::new([0u8; 12]);
    hkdf_content
        .expand(b"Content-Encoding: nonce\0", &mut *nonce_bytes)
        .expect("12-byte HKDF output is valid");

    // Pad plaintext with final record delimiter 0x02 and encrypt
    let mut padded = Vec::with_capacity(plaintext.len() + 1);
    padded.extend_from_slice(plaintext);
    padded.push(FINAL_RECORD_DELIMITER);

    let cipher = Aes128Gcm::new_from_slice(&*cek).expect("16-byte AES-128 key is valid");
    let nonce = Nonce::from(*nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, padded.as_slice())
        .map_err(|_| EncryptionError::EncryptFailed)?;

    // Build RFC 8188 header: salt (16) || rs (4) || idlen (1) || keyid (65) || ciphertext
    let mut out = Vec::with_capacity(SALT_LEN + 4 + 1 + UNCOMPRESSED_PUBKEY_LEN + ciphertext.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    out.push(UNCOMPRESSED_PUBKEY_IDLEN);
    out.extend_from_slice(as_pub_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decrypts an RFC 8291 `aes128gcm` message using the receiver's private key
    /// and auth secret to verify full end-to-end correctness.
    fn decrypt_aes128gcm(body: &[u8], ua_private: &SecretKey, auth_secret: &[u8]) -> Vec<u8> {
        let salt = &body[0..16];
        let rs = u32::from_be_bytes(body[16..20].try_into().unwrap());
        assert_eq!(rs, RECORD_SIZE);
        let idlen = body[20] as usize;
        assert_eq!(idlen, UNCOMPRESSED_PUBKEY_LEN);
        let as_pub_bytes = &body[21..21 + idlen];
        let ciphertext = &body[21 + idlen..];

        let as_public = PublicKey::from_sec1_bytes(as_pub_bytes).unwrap();
        let ua_pub_point = ua_private.public_key().to_sec1_point(false);

        let shared_secret =
            p256::ecdh::diffie_hellman(ua_private.to_nonzero_scalar(), as_public.as_affine());

        let mut key_info = Vec::new();
        key_info.extend_from_slice(b"WebPush: info\0");
        key_info.extend_from_slice(ua_pub_point.as_bytes());
        key_info.extend_from_slice(as_pub_bytes);

        let hkdf_auth = Hkdf::<Sha256>::new(Some(auth_secret), shared_secret.raw_secret_bytes());
        let mut ikm = [0u8; 32];
        hkdf_auth.expand(&key_info, &mut ikm).unwrap();

        let hkdf_content = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut cek = [0u8; 16];
        hkdf_content
            .expand(b"Content-Encoding: aes128gcm\0", &mut cek)
            .unwrap();
        let mut nonce_bytes = [0u8; 12];
        hkdf_content
            .expand(b"Content-Encoding: nonce\0", &mut nonce_bytes)
            .unwrap();

        let cipher = Aes128Gcm::new_from_slice(&cek).unwrap();
        let mut decrypted = cipher
            .decrypt(&Nonce::from(nonce_bytes), ciphertext)
            .unwrap();
        assert_eq!(decrypted.pop(), Some(FINAL_RECORD_DELIMITER));
        decrypted
    }

    #[test]
    fn roundtrip_encrypt_and_decrypt() {
        let ua_private = generate_p256_secret_key().unwrap();
        let ua_pub_b64 = URL_SAFE_NO_PAD.encode(ua_private.public_key().to_sec1_point(false));
        let mut auth = [0u8; 16];
        getrandom::fill(&mut auth).unwrap();
        let auth_b64 = URL_SAFE_NO_PAD.encode(auth);

        let plaintext = br#"{"web_push":8030,"notification":{"title":"Selvedge"}}"#;
        let encrypted = encrypt_aes128gcm(plaintext, &ua_pub_b64, &auth_b64).unwrap();
        let decrypted = decrypt_aes128gcm(&encrypted, &ua_private, &auth);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn matches_rfc8291_section5_test_vector() {
        // RFC 8291 Section 5 test vector inputs
        let ua_private_bytes = URL_SAFE_NO_PAD
            .decode("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")
            .unwrap();
        let ua_private = SecretKey::from_slice(&ua_private_bytes).unwrap();
        let as_private_bytes = URL_SAFE_NO_PAD
            .decode("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")
            .unwrap();
        let as_private = SecretKey::from_slice(&as_private_bytes).unwrap();
        let auth_secret = URL_SAFE_NO_PAD.decode("BTBZMqHH6r4Tts7J_aSIgg").unwrap();
        let salt: [u8; 16] = URL_SAFE_NO_PAD
            .decode("DGv6ra1nlYgDCS1FRnbzlw")
            .unwrap()
            .try_into()
            .unwrap();

        let plaintext = b"When I grow up, I want to be a watermelon";
        let encrypted = encrypt_with_params(
            plaintext,
            &ua_private.public_key(),
            &auth_secret,
            &as_private,
            &salt,
        )
        .unwrap();

        let decrypted = decrypt_aes128gcm(&encrypted, &ua_private, &auth_secret);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_invalid_keys() {
        assert!(matches!(
            encrypt_aes128gcm(b"hi", "not-valid-key", "BTBZMqHH6r4Tts7J_aSIgg"),
            Err(EncryptionError::InvalidP256dh)
        ));

        let ua_private = generate_p256_secret_key().unwrap();
        let ua_pub_b64 = URL_SAFE_NO_PAD.encode(ua_private.public_key().to_sec1_point(false));
        assert!(matches!(
            encrypt_aes128gcm(b"hi", &ua_pub_b64, "short"),
            Err(EncryptionError::InvalidAuthSecret)
        ));
    }

    #[test]
    fn enforces_4096_byte_total_body_limit() {
        let ua_private = generate_p256_secret_key().unwrap();
        let ua_pub_b64 = URL_SAFE_NO_PAD.encode(ua_private.public_key().to_sec1_point(false));
        let auth_b64 = URL_SAFE_NO_PAD.encode([7u8; 16]);

        let max_body =
            encrypt_aes128gcm(&vec![b'a'; MAX_PLAINTEXT_LEN], &ua_pub_b64, &auth_b64).unwrap();
        assert_eq!(max_body.len(), RECORD_SIZE as usize);

        assert!(matches!(
            encrypt_aes128gcm(&vec![b'a'; MAX_PLAINTEXT_LEN + 1], &ua_pub_b64, &auth_b64),
            Err(EncryptionError::PayloadTooLarge)
        ));
    }
}
