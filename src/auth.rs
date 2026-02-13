use std::collections::{BTreeMap, HashSet};

use axum::{
    extract::State,
    http::{HeaderMap, Request, header},
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde_json::Value;
use sha2::Sha256;
use sqlx::Row;

use crate::{
    error::AppError,
    models::{BootstrapClaims, CapabilityClaims, ResourceScope},
    state::AppState,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct AuthContext {
    pub claims: CapabilityClaims,
    pub mtls_subject: String,
}

#[derive(Clone, Debug)]
pub struct BootstrapAuthContext {
    pub claims: BootstrapClaims,
    pub mtls_subject: String,
}

impl AuthContext {
    pub fn allows_scope(&self, kind: &str, id: &str) -> bool {
        self.claims
            .resource_scopes
            .iter()
            .any(|scope| scope.kind == kind && (scope.id == id || scope.id == "*"))
    }
}

impl BootstrapAuthContext {
    pub fn agent_id(&self) -> String {
        self.claims
            .sub
            .strip_prefix("agent:")
            .unwrap_or(&self.claims.sub)
            .to_string()
    }
}

pub async fn bootstrap_auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    let mtls_subject = extract_and_verify_mtls_subject(
        request.headers(),
        &state.config.mtls_binding_shared_secret,
    )?;
    let token = bearer_token(request.headers())?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(std::slice::from_ref(&state.config.bootstrap_jwt_audience));
    validation.set_issuer(std::slice::from_ref(&state.config.bootstrap_jwt_issuer));
    validation.leeway = 30;

    let decoded = decode::<BootstrapClaims>(
        &token,
        &DecodingKey::from_secret(state.config.bootstrap_jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::Unauthorized("invalid bootstrap token".to_string()))?;

    if decoded.claims.bindings.mtls_subject != mtls_subject {
        return Err(AppError::Forbidden(
            "bootstrap token binding mismatch for mTLS subject".to_string(),
        ));
    }

    request.extensions_mut().insert(BootstrapAuthContext {
        claims: decoded.claims,
        mtls_subject,
    });

    Ok(next.run(request).await)
}

pub async fn capability_auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    let mtls_subject = extract_and_verify_mtls_subject(
        request.headers(),
        &state.config.mtls_binding_shared_secret,
    )?;
    let token = bearer_token(request.headers())?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(std::slice::from_ref(&state.config.jwt_audience));
    validation.set_issuer(std::slice::from_ref(&state.config.jwt_issuer));
    validation.leeway = 30;

    let decoded = decode::<CapabilityClaims>(
        &token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::Unauthorized("invalid capability token".to_string()))?;

    if decoded.claims.bindings.mtls_subject != mtls_subject {
        return Err(AppError::Forbidden(
            "capability binding mismatch for mTLS subject".to_string(),
        ));
    }

    let row = sqlx::query(
        r#"
        SELECT task_id, agent_id, mtls_subject, aud, iss, expires_at, revoked_at, rev, claims_hash
        FROM capability_tokens
        WHERE jti = ?1
        "#,
    )
    .bind(decoded.claims.jti.clone())
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Err(AppError::Unauthorized(
            "unknown capability token".to_string(),
        ));
    };

    let db_task_id: Option<String> = row.try_get("task_id")?;
    let db_agent_id: String = row.try_get("agent_id")?;
    let db_mtls_subject: String = row.try_get("mtls_subject")?;
    let db_aud: String = row.try_get("aud")?;
    let db_iss: String = row.try_get("iss")?;
    let db_expires_at: chrono::DateTime<Utc> = row.try_get("expires_at")?;
    let revoked_at: Option<chrono::DateTime<Utc>> = row.try_get("revoked_at")?;
    let db_rev: i64 = row.try_get("rev")?;
    let db_claims_hash: String = row.try_get("claims_hash")?;

    if revoked_at.is_some() {
        return Err(AppError::Unauthorized(
            "capability token revoked".to_string(),
        ));
    }
    if db_expires_at < Utc::now() {
        return Err(AppError::Unauthorized(
            "capability token expired".to_string(),
        ));
    }

    if db_task_id != decoded.claims.task_id
        || db_agent_id != decoded.claims.agent_id
        || db_mtls_subject != decoded.claims.bindings.mtls_subject
        || db_aud != decoded.claims.aud
        || db_iss != decoded.claims.iss
        || db_rev != decoded.claims.perms_rev
        || db_expires_at.timestamp() != decoded.claims.exp as i64
    {
        return Err(AppError::Unauthorized(
            "capability token DB claims mismatch".to_string(),
        ));
    }

    let claims_hash = capability_claims_hash(&decoded.claims)?;
    if claims_hash != db_claims_hash {
        return Err(AppError::Unauthorized(
            "capability token integrity mismatch".to_string(),
        ));
    }

    request.extensions_mut().insert(AuthContext {
        claims: decoded.claims,
        mtls_subject,
    });

    Ok(next.run(request).await)
}

pub fn extract_and_verify_mtls_subject(
    headers: &HeaderMap,
    shared_secret: &str,
) -> Result<String, AppError> {
    if shared_secret.trim().is_empty() {
        return Err(AppError::Unauthorized(
            "mTLS binding secret is not configured".to_string(),
        ));
    }

    let subject = headers
        .get("x-client-subject")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::Unauthorized("missing x-client-subject".to_string()))?
        .to_string();

    let ts_raw = headers
        .get("x-client-subject-ts")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::Unauthorized("missing x-client-subject-ts".to_string()))?;
    let ts = ts_raw
        .parse::<i64>()
        .map_err(|_| AppError::Unauthorized("invalid x-client-subject-ts".to_string()))?;

    let now_ts = Utc::now().timestamp();
    if (now_ts - ts).abs() > 60 {
        return Err(AppError::Unauthorized(
            "stale x-client-subject-ts".to_string(),
        ));
    }

    let sig_hex = headers
        .get("x-client-subject-sig")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::Unauthorized("missing x-client-subject-sig".to_string()))?;

    let provided_sig = hex::decode(sig_hex)
        .map_err(|_| AppError::Unauthorized("invalid x-client-subject-sig".to_string()))?;

    let mut mac = HmacSha256::new_from_slice(shared_secret.as_bytes())
        .map_err(|e| AppError::internal(format!("failed to init mTLS binding hmac: {e}")))?;
    mac.update(format!("{subject}\n{ts}").as_bytes());
    mac.verify_slice(&provided_sig)
        .map_err(|_| AppError::Unauthorized("invalid x-client-subject-sig".to_string()))?;

    Ok(subject)
}

pub fn issue_capability_token(
    claims: &CapabilityClaims,
    jwt_secret: &str,
) -> Result<String, AppError> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::internal(format!("failed to sign capability token: {e}")))
}

pub fn issue_bootstrap_token(
    claims: &BootstrapClaims,
    jwt_secret: &str,
) -> Result<String, AppError> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::internal(format!("failed to sign bootstrap token: {e}")))
}

#[allow(clippy::too_many_arguments)]
pub fn make_capability_claims(
    issuer: &str,
    audience: &str,
    agent_id: &str,
    task_id: Option<String>,
    jti: String,
    ttl_seconds: i64,
    mtls_subject: String,
    allowed_ops: Vec<String>,
    resource_scopes: Vec<ResourceScope>,
    perms_rev: i64,
) -> CapabilityClaims {
    let now = Utc::now().timestamp() as usize;
    let exp = (Utc::now() + chrono::Duration::seconds(ttl_seconds)).timestamp() as usize;

    CapabilityClaims {
        iss: issuer.to_string(),
        sub: format!("agent:{agent_id}"),
        aud: audience.to_string(),
        jti,
        iat: now,
        nbf: now,
        exp,
        task_id,
        agent_id: agent_id.to_string(),
        allowed_ops,
        resource_scopes,
        bindings: crate::models::CapabilityBindings { mtls_subject },
        perms_rev,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn make_bootstrap_claims(
    issuer: &str,
    audience: &str,
    subject: &str,
    jti: String,
    ttl_seconds: i64,
    mtls_subject: String,
    can_issue_tasks: bool,
    can_manage_permissions: bool,
    can_manage_approvers: bool,
) -> BootstrapClaims {
    let now = Utc::now().timestamp() as usize;
    let exp = (Utc::now() + chrono::Duration::seconds(ttl_seconds)).timestamp() as usize;
    BootstrapClaims {
        iss: issuer.to_string(),
        sub: subject.to_string(),
        aud: audience.to_string(),
        jti,
        iat: now,
        nbf: now,
        exp,
        bindings: crate::models::CapabilityBindings { mtls_subject },
        can_issue_tasks,
        can_manage_permissions,
        can_manage_approvers,
    }
}

pub fn bearer_token(headers: &HeaderMap) -> Result<String, AppError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;

    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("authorization must be Bearer token".to_string()))?;

    Ok(token.to_string())
}

pub fn ensure_task_access(auth: &AuthContext, task_id: &str) -> Result<(), AppError> {
    if auth.claims.task_id.as_deref() != Some(task_id) {
        return Err(AppError::Forbidden(
            "capability token does not grant this task".to_string(),
        ));
    }

    Ok(())
}

pub fn ensure_ops_subset(auth: &AuthContext, operations: &[String]) -> Result<(), AppError> {
    let allowed: HashSet<&str> = auth.claims.allowed_ops.iter().map(String::as_str).collect();
    for op in operations {
        if !allowed.contains(op.as_str()) {
            return Err(AppError::Forbidden(format!(
                "operation not allowed by capability: {op}"
            )));
        }
    }
    Ok(())
}

pub fn ensure_scopes_subset(
    auth: &AuthContext,
    scope_pairs: &[(String, String)],
) -> Result<(), AppError> {
    for (kind, id) in scope_pairs {
        if !auth.allows_scope(kind, id) {
            return Err(AppError::Forbidden(format!(
                "scope {kind}:{id} not allowed by capability"
            )));
        }
    }

    Ok(())
}

pub fn parse_json_field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.get(key)
}

pub fn capability_claims_hash(claims: &CapabilityClaims) -> Result<String, AppError> {
    let value = serde_json::to_value(claims).map_err(AppError::internal)?;
    let canonical = canonicalize_json(&value);
    let bytes = serde_json::to_vec(&canonical).map_err(AppError::internal)?;
    Ok(crate::db::sha256_hex_bytes(&bytes))
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut ordered = BTreeMap::new();
            for (k, v) in map {
                ordered.insert(k.clone(), canonicalize_json(v));
            }
            let mut out = serde_json::Map::new();
            for (k, v) in ordered {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthContext, bearer_token, capability_claims_hash, ensure_ops_subset, ensure_scopes_subset,
        extract_and_verify_mtls_subject, make_bootstrap_claims, make_capability_claims,
        parse_json_field,
    };
    use crate::models::{CapabilityBindings, CapabilityClaims, PermissionLevel, ResourceScope};
    use axum::http::{HeaderMap, HeaderValue, header};
    use serde_json::json;

    fn auth_context() -> AuthContext {
        let claims = CapabilityClaims {
            iss: "issuer".to_string(),
            sub: "agent:agent-1".to_string(),
            aud: "aud".to_string(),
            jti: "jti-1".to_string(),
            iat: 1,
            nbf: 1,
            exp: 2,
            task_id: Some("task-1".to_string()),
            agent_id: "agent-1".to_string(),
            allowed_ops: vec!["dns.record.read".to_string()],
            resource_scopes: vec![
                ResourceScope {
                    kind: "zone".to_string(),
                    id: "zone-a".to_string(),
                },
                ResourceScope {
                    kind: "account".to_string(),
                    id: "*".to_string(),
                },
            ],
            bindings: CapabilityBindings {
                mtls_subject: "device-1".to_string(),
            },
            perms_rev: 1,
        };

        AuthContext {
            claims,
            mtls_subject: "device-1".to_string(),
        }
    }

    #[test]
    fn bearer_token_parses_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc.def"),
        );
        let token = bearer_token(&headers).expect("token parse should succeed");
        assert_eq!(token, "abc.def");
    }

    #[test]
    fn verify_mtls_subject_requires_signature_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-client-subject", HeaderValue::from_static("device-1"));
        let err = extract_and_verify_mtls_subject(&headers, "secret")
            .expect_err("timestamp and signature headers must be required");
        assert!(err.to_string().contains("x-client-subject-ts"));
    }

    #[test]
    fn ensure_scope_subset_allows_wildcards_and_denies_out_of_scope() {
        let auth = auth_context();
        ensure_scopes_subset(
            &auth,
            &[
                ("zone".to_string(), "zone-a".to_string()),
                ("account".to_string(), "account-x".to_string()),
            ],
        )
        .expect("scope set should be allowed");

        let err = ensure_scopes_subset(&auth, &[("zone".to_string(), "zone-b".to_string())])
            .expect_err("out-of-scope request should fail");
        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn ensure_ops_subset_rejects_unlisted_operation() {
        let auth = auth_context();
        let err = ensure_ops_subset(&auth, &["waf.rules.write".to_string()])
            .expect_err("operation should be denied");
        assert!(err.to_string().contains("operation not allowed"));
    }

    #[test]
    fn make_capability_claims_sets_expected_fields() {
        let claims = make_capability_claims(
            "issuer-x",
            "aud-x",
            "agent-9",
            Some("task-9".to_string()),
            "jti-x".to_string(),
            120,
            "mtls-x".to_string(),
            vec!["dns.record.read".to_string()],
            vec![ResourceScope {
                kind: "zone".to_string(),
                id: "z1".to_string(),
            }],
            7,
        );
        assert_eq!(claims.iss, "issuer-x");
        assert_eq!(claims.aud, "aud-x");
        assert_eq!(claims.agent_id, "agent-9");
        assert_eq!(claims.task_id.as_deref(), Some("task-9"));
        assert_eq!(claims.bindings.mtls_subject, "mtls-x");
        assert_eq!(claims.perms_rev, 7);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn make_bootstrap_claims_sets_permissions() {
        let claims = make_bootstrap_claims(
            "iss",
            "aud",
            "agent:issuer",
            "jti".to_string(),
            60,
            "mtls".to_string(),
            true,
            true,
            false,
        );
        assert!(claims.can_issue_tasks);
        assert!(claims.can_manage_permissions);
        assert!(!claims.can_manage_approvers);
    }

    #[test]
    fn parse_json_field_extracts_value() {
        let value = json!({"level": PermissionLevel::Read, "count": 1});
        let field = parse_json_field(&value, "count").expect("field should exist");
        assert_eq!(field.as_i64(), Some(1));
    }

    #[test]
    fn capability_claims_hash_is_stable_for_equivalent_claims() {
        let claims = make_capability_claims(
            "issuer-x",
            "aud-x",
            "agent-9",
            Some("task-9".to_string()),
            "jti-x".to_string(),
            120,
            "mtls-x".to_string(),
            vec!["dns.record.read".to_string()],
            vec![ResourceScope {
                kind: "zone".to_string(),
                id: "z1".to_string(),
            }],
            7,
        );
        let hash_a = capability_claims_hash(&claims).expect("hash should compute");
        let hash_b = capability_claims_hash(&claims).expect("hash should compute");
        assert_eq!(hash_a, hash_b);
    }
}
