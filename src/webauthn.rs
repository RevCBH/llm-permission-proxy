use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::Deserialize;
use serde_cbor::Value;
use serde_json;
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
        return Err(AppError::Forbidden(
            "webauthn challenge mismatch".to_string(),
        ));
    }

    if parsed.origin != expected_origin {
        return Err(AppError::Forbidden("webauthn origin mismatch".to_string()));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
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
        return Err(AppError::BadRequest(
            "authenticator_data is malformed".to_string(),
        ));
    }

    let rp_id_hash = Sha256::digest(expected_rp_id.as_bytes());
    if authenticator_data[..32] != rp_id_hash[..] {
        return Err(AppError::Forbidden(
            "webauthn rp_id hash mismatch".to_string(),
        ));
    }

    let flags = authenticator_data[32];
    if flags & USER_PRESENT_BIT == 0 {
        return Err(AppError::Forbidden(
            "webauthn user presence required".to_string(),
        ));
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

#[cfg(test)]
mod tests {
    use super::verify_assertion;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::{
        EncodedPoint,
        ecdsa::{Signature, SigningKey, signature::Signer},
    };
    use serde_cbor::Value;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[
            0x01, 0x9f, 0x13, 0x08, 0xa1, 0xef, 0x56, 0x2c, 0x88, 0x7c, 0xbe, 0x12, 0x42, 0x1d,
            0x29, 0x66, 0xde, 0x11, 0x8f, 0x43, 0xac, 0xcd, 0x02, 0xe1, 0xaa, 0xbb, 0x7d, 0x0f,
            0x41, 0x22, 0x5b, 0x6a,
        ])
        .expect("valid private key")
    }

    fn cose_key_b64(signing_key: &SigningKey) -> String {
        let verifying = signing_key.verifying_key();
        let point: EncodedPoint = verifying.to_encoded_point(false);
        let bytes = point.as_bytes();
        let x = bytes[1..33].to_vec();
        let y = bytes[33..65].to_vec();

        let mut map = BTreeMap::new();
        map.insert(Value::Integer(1), Value::Integer(2));
        map.insert(Value::Integer(3), Value::Integer(-7));
        map.insert(Value::Integer(-1), Value::Integer(1));
        map.insert(Value::Integer(-2), Value::Bytes(x));
        map.insert(Value::Integer(-3), Value::Bytes(y));
        let cbor = Value::Map(map);
        let encoded = serde_cbor::to_vec(&cbor).expect("cbor serialization should succeed");
        URL_SAFE_NO_PAD.encode(encoded)
    }

    fn make_authenticator_data(rp_id: &str, flags: u8) -> Vec<u8> {
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        auth_data.push(flags);
        auth_data.extend_from_slice(&0_u32.to_be_bytes());
        auth_data
    }

    fn client_data_json_b64(challenge: &str, origin: &str) -> String {
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "type": "webauthn.get",
                "challenge": challenge,
                "origin": origin
            }))
            .expect("client data json should serialize"),
        )
    }

    fn signature_b64(
        signing_key: &SigningKey,
        authenticator_data: &[u8],
        client_data_b64: &str,
    ) -> String {
        let client_data = URL_SAFE_NO_PAD
            .decode(client_data_b64)
            .expect("client data should decode");
        let client_hash = Sha256::digest(client_data);
        let mut signed_data = authenticator_data.to_vec();
        signed_data.extend_from_slice(&client_hash);
        let signature: Signature = signing_key.sign(&signed_data);
        URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())
    }

    #[test]
    fn verify_assertion_accepts_valid_es256_signature() {
        let rp_id = "localhost";
        let origin = "http://localhost:8080";
        let challenge = "challenge-123";
        let key = signing_key();

        let client_data = client_data_json_b64(challenge, origin);
        let authenticator_data = make_authenticator_data(rp_id, 0x05);
        let signature = signature_b64(&key, &authenticator_data, &client_data);

        verify_assertion(
            &client_data,
            challenge,
            origin,
            rp_id,
            true,
            "ES256",
            "cose",
            &cose_key_b64(&key),
            &URL_SAFE_NO_PAD.encode(&authenticator_data),
            &signature,
        )
        .expect("valid assertion should pass");
    }

    #[test]
    fn verify_assertion_rejects_challenge_mismatch() {
        let rp_id = "localhost";
        let origin = "http://localhost:8080";
        let key = signing_key();

        let client_data = client_data_json_b64("challenge-a", origin);
        let authenticator_data = make_authenticator_data(rp_id, 0x05);
        let signature = signature_b64(&key, &authenticator_data, &client_data);

        let err = verify_assertion(
            &client_data,
            "challenge-b",
            origin,
            rp_id,
            true,
            "ES256",
            "cose",
            &cose_key_b64(&key),
            &URL_SAFE_NO_PAD.encode(&authenticator_data),
            &signature,
        )
        .expect_err("challenge mismatch should fail");

        assert!(err.to_string().contains("challenge mismatch"));
    }

    #[test]
    fn verify_assertion_rejects_origin_mismatch() {
        let rp_id = "localhost";
        let key = signing_key();

        let client_data = client_data_json_b64("challenge-a", "http://localhost:8080");
        let authenticator_data = make_authenticator_data(rp_id, 0x05);
        let signature = signature_b64(&key, &authenticator_data, &client_data);

        let err = verify_assertion(
            &client_data,
            "challenge-a",
            "https://wrong-origin",
            rp_id,
            true,
            "ES256",
            "cose",
            &cose_key_b64(&key),
            &URL_SAFE_NO_PAD.encode(&authenticator_data),
            &signature,
        )
        .expect_err("origin mismatch should fail");

        assert!(err.to_string().contains("origin mismatch"));
    }

    #[test]
    fn verify_assertion_rejects_rp_id_hash_mismatch() {
        let key = signing_key();
        let challenge = "challenge-rp";
        let origin = "http://localhost:8080";

        let client_data = client_data_json_b64(challenge, origin);
        let authenticator_data = make_authenticator_data("localhost", 0x05);
        let signature = signature_b64(&key, &authenticator_data, &client_data);

        let err = verify_assertion(
            &client_data,
            challenge,
            origin,
            "different-rp-id",
            true,
            "ES256",
            "cose",
            &cose_key_b64(&key),
            &URL_SAFE_NO_PAD.encode(&authenticator_data),
            &signature,
        )
        .expect_err("rp mismatch should fail");

        assert!(err.to_string().contains("rp_id hash mismatch"));
    }

    #[test]
    fn verify_assertion_rejects_missing_user_verification() {
        let rp_id = "localhost";
        let origin = "http://localhost:8080";
        let challenge = "challenge-uv";
        let key = signing_key();

        let client_data = client_data_json_b64(challenge, origin);
        let authenticator_data = make_authenticator_data(rp_id, 0x01);
        let signature = signature_b64(&key, &authenticator_data, &client_data);

        let err = verify_assertion(
            &client_data,
            challenge,
            origin,
            rp_id,
            true,
            "ES256",
            "cose",
            &cose_key_b64(&key),
            &URL_SAFE_NO_PAD.encode(&authenticator_data),
            &signature,
        )
        .expect_err("missing uv should fail");

        assert!(err.to_string().contains("user verification required"));
    }

    #[test]
    fn verify_assertion_rejects_bad_signature() {
        let rp_id = "localhost";
        let origin = "http://localhost:8080";
        let challenge = "challenge-sig";
        let key = signing_key();

        let client_data = client_data_json_b64(challenge, origin);
        let authenticator_data = make_authenticator_data(rp_id, 0x05);
        let mut signature = URL_SAFE_NO_PAD
            .decode(signature_b64(&key, &authenticator_data, &client_data))
            .expect("signature must decode");
        signature[0] ^= 0x01;

        let err = verify_assertion(
            &client_data,
            challenge,
            origin,
            rp_id,
            true,
            "ES256",
            "cose",
            &cose_key_b64(&key),
            &URL_SAFE_NO_PAD.encode(&authenticator_data),
            &URL_SAFE_NO_PAD.encode(signature),
        )
        .expect_err("invalid signature should fail");

        assert!(
            err.to_string()
                .contains("invalid authenticator assertion signature encoding")
                || err.to_string().contains("signature verification failed")
        );
    }
}
