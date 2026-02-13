use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Deserialize;
use serde_json;
use serde_cbor::Value;
use sha2::{Digest, Sha256};

use crate::error::AppError;

const USER_PRESENT_BIT: u8 = 0x01;
const USER_VERIFIED_BIT: u8 = 0x04;

#[derive(Debug, Deserialize)]
struct CollectedClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
}

pub fn verify_client_data_json(
    client_data_json_b64: &str,
    expected_challenge: &str,
    expected_origin: &str,
) -> Result<(), AppError> {
    let bytes = decode_b64url(client_data_json_b64)?;
    let parsed: CollectedClientData = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::BadRequest("invalid client_data_json payload".to_string()))?;

    if parsed.typ != "webauthn.get" {
        return Err(AppError::BadRequest(
            "invalid client_data_json type for authentication".to_string(),
        ));
    }

    if parsed.challenge != expected_challenge {
        return Err(AppError::Forbidden("webauthn challenge mismatch".to_string()));
    }

    if parsed.origin != expected_origin {
        return Err(AppError::Forbidden("webauthn origin mismatch".to_string()));
    }

    Ok(())
}

pub fn verify_assertion(
    client_data_json_b64: &str,
    expected_challenge: &str,
    expected_origin: &str,
    expected_rp_id: &str,
    user_verification_required: bool,
    algorithm: &str,
    public_key_format: &str,
    public_key_b64: &str,
    authenticator_data_b64: &str,
    signature_b64: &str,
) -> Result<(), AppError> {
    verify_client_data_json(client_data_json_b64, expected_challenge, expected_origin)?;

    let authenticator_data = decode_b64url(authenticator_data_b64)?;
    if authenticator_data.len() < 37 {
        return Err(AppError::BadRequest("authenticator_data is malformed".to_string()));
    }

    let rp_id_hash = Sha256::digest(expected_rp_id.as_bytes());
    if authenticator_data[..32] != rp_id_hash[..] {
        return Err(AppError::Forbidden("webauthn rp_id hash mismatch".to_string()));
    }

    let flags = authenticator_data[32];
    if flags & USER_PRESENT_BIT == 0 {
        return Err(AppError::Forbidden("webauthn user presence required".to_string()));
    }
    if user_verification_required && flags & USER_VERIFIED_BIT == 0 {
        return Err(AppError::Forbidden(
            "webauthn user verification required".to_string(),
        ));
    }

    validate_webauthn_credential_key(algorithm, public_key_format, public_key_b64)?;
    let public_key = parse_cose_p256_public_key(public_key_b64)?;

    let client_data_json = decode_b64url(client_data_json_b64)?;
    let client_data_hash = Sha256::digest(&client_data_json);

    let mut signed_data = authenticator_data;
    signed_data.extend_from_slice(&client_data_hash);

    let signature = decode_signature(signature_b64)?;
    public_key
        .verify(&signed_data, &signature)
        .map_err(|_| AppError::Forbidden("webauthn signature verification failed".to_string()))?;

    Ok(())
}

pub fn validate_webauthn_credential_key(
    algorithm: &str,
    public_key_format: &str,
    public_key_b64: &str,
) -> Result<(), AppError> {
    let normalized_algorithm = algorithm.trim().to_ascii_uppercase();
    if normalized_algorithm != "ES256" {
        return Err(AppError::BadRequest(
            "unsupported algorithm: only ES256 is supported".to_string(),
        ));
    }

    let normalized_format = public_key_format.trim().to_ascii_lowercase();
    if normalized_format != "cose" {
        return Err(AppError::BadRequest(
            "unsupported public key format: only cose is supported".to_string(),
        ));
    }

    parse_cose_p256_public_key(public_key_b64)?;
    Ok(())
}

fn parse_cose_p256_public_key(public_key_b64: &str) -> Result<VerifyingKey, AppError> {
    let key_bytes = decode_b64url(public_key_b64)?;
    let cbor: Value = serde_cbor::from_slice(&key_bytes)
        .map_err(|_| AppError::BadRequest("invalid COSE public key encoding".to_string()))?;

    let map = match cbor {
        Value::Map(entries) => entries,
        _ => {
            return Err(AppError::BadRequest(
                "invalid COSE key: expected map".to_string(),
            ));
        }
    };

    let mut kty = None;
    let mut alg = None;
    let mut crv = None;
    let mut x = None;
    let mut y = None;

    for (k, v) in map {
        if let Some(key) = integer_key(&k) {
            match key {
                1 => kty = int_value(&v),
                3 => alg = int_value(&v),
                -1 => crv = int_value(&v),
                -2 => x = bytes_value(&v),
                -3 => y = bytes_value(&v),
                _ => {}
            }
        }
    }

    // COSE EC2 + ES256
    if !matches!(kty, Some(2)) || !matches!(alg, Some(-7)) || !matches!(crv, Some(1)) {
        return Err(AppError::BadRequest(
            "unsupported COSE key type or algorithm".to_string(),
        ));
    }

    let x = x.ok_or_else(|| AppError::BadRequest("missing COSE x coordinate".to_string()))?;
    let y = y.ok_or_else(|| AppError::BadRequest("missing COSE y coordinate".to_string()))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(AppError::BadRequest(
            "invalid EC coordinate length".to_string(),
        ));
    }

    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);

    VerifyingKey::from_sec1_bytes(&point)
        .map_err(|_| AppError::BadRequest("invalid EC public key".to_string()))
}

fn decode_signature(signature_b64: &str) -> Result<Signature, AppError> {
    let bytes = decode_b64url(signature_b64)?;
    Signature::from_der(&bytes).map_err(|_| {
        AppError::BadRequest("invalid authenticator assertion signature encoding".to_string())
    })
}

fn integer_key(key: &Value) -> Option<i64> {
    match key {
        Value::Integer(v) => Some(*v as i64),
        _ => None,
    }
}

fn int_value(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(v) => Some(*v as i64),
        _ => None,
    }
}

fn bytes_value(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Bytes(v) => Some(v.clone()),
        _ => None,
    }
}

fn decode_b64url(value: &str) -> Result<Vec<u8>, AppError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::BadRequest("invalid base64url encoding".to_string()))
}
