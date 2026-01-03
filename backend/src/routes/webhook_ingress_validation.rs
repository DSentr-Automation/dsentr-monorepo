use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use time::OffsetDateTime;

use crate::models::webhook_source::WebhookSource;
use crate::utils::encryption::{decrypt_secret, EncryptionError};

type HmacSha256 = Hmac<Sha256>;

// Inbound webhook timestamp header used for replay protection.
pub const TIMESTAMP_HEADER: &str = "X-DSentr-Timestamp";
// Inbound webhook signature header ("v1=<hex>" or raw hex HMAC).
pub const SIGNATURE_HEADER: &str = "X-DSentr-Signature";
const SIGNATURE_PREFIX: &str = "v1=";

#[derive(Debug)]
pub enum WebhookSignatureError {
    DecryptFailed(EncryptionError),
    ValidationFailed(&'static str),
}

pub fn validate_webhook_signature(
    encryption_key: &[u8],
    source: &WebhookSource,
    headers: &HeaderMap,
    body: &[u8],
    now: OffsetDateTime,
) -> Result<(), WebhookSignatureError> {
    let secret = decrypt_secret(encryption_key, &source.secret)
        .map_err(WebhookSignatureError::DecryptFailed)?;
    validate_signature(&secret, source, headers, body, now)
        .map_err(WebhookSignatureError::ValidationFailed)
}

fn validate_signature(
    secret: &str,
    source: &WebhookSource,
    headers: &HeaderMap,
    body: &[u8],
    now: OffsetDateTime,
) -> Result<(), &'static str> {
    let timestamp = header_value(headers, TIMESTAMP_HEADER).ok_or("Missing timestamp header")?;
    let signature = header_value(headers, SIGNATURE_HEADER).ok_or("Missing signature header")?;

    let ts = timestamp.parse::<i64>().map_err(|_| "Invalid timestamp")?;
    if ts <= 0 {
        return Err("Invalid timestamp");
    }

    let window = source.replay_window_sec.max(0) as i64;
    if window > 0 {
        let now_ts = now.unix_timestamp();
        if (now_ts - ts).abs() > window {
            return Err("Replay window exceeded");
        }
    }

    let provided = signature
        .trim()
        .strip_prefix(SIGNATURE_PREFIX)
        .unwrap_or(signature);
    let expected = compute_signature(secret, timestamp, body)?;

    if subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), provided.as_bytes()).unwrap_u8() == 0u8 {
        return Err("Invalid signature");
    }

    Ok(())
}

pub(crate) fn compute_signature(
    secret: &str,
    timestamp: &str,
    body: &[u8],
) -> Result<String, &'static str> {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| "Invalid signature key")?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}
