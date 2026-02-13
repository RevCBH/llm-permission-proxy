use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

use crate::error::AppError;

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
    let bytes = URL_SAFE_NO_PAD
        .decode(client_data_json_b64)
        .map_err(|_| AppError::BadRequest("invalid client_data_json encoding".to_string()))?;

    let parsed: CollectedClientData = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::BadRequest("invalid client_data_json payload".to_string()))?;

    if parsed.typ != "webauthn.get" {
        return Err(AppError::BadRequest(
            "invalid client_data_json type for authentication".to_string(),
        ));
    }

    if parsed.challenge != expected_challenge {
        return Err(AppError::Forbidden(
            "webauthn challenge mismatch".to_string(),
        ));
    }

    if parsed.origin != expected_origin {
        return Err(AppError::Forbidden("webauthn origin mismatch".to_string()));
    }

    Ok(())
}
