use std::collections::HashSet;

use axum::{
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde_json::Value;
use sqlx::Row;

use crate::{
    error::AppError,
    models::{CapabilityClaims, ResourceScope},
    state::AppState,
};

#[derive(Clone, Debug)]
pub struct AuthContext {
    pub claims: CapabilityClaims,
    pub mtls_subject: String,
}

impl AuthContext {
    pub fn is_admin(&self) -> bool {
        self.claims.allowed_ops.iter().any(|op| op == "permissions.admin")
    }

    pub fn allows_operation(&self, operation_id: &str) -> bool {
        self.claims.allowed_ops.iter().any(|op| op == operation_id)
    }

    pub fn allows_scope(&self, kind: &str, id: &str) -> bool {
        self.claims
            .resource_scopes
            .iter()
            .any(|scope| scope.kind == kind && (scope.id == id || scope.id == "*"))
    }
}

pub fn extract_mtls_subject(headers: &HeaderMap) -> Result<String, AppError> {
    let subject = headers
        .get("x-client-subject")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::Unauthorized("missing x-client-subject (mTLS identity)".to_string()))?;

    Ok(subject.to_string())
}

pub async fn capability_auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    let mtls_subject = extract_mtls_subject(request.headers())?;
    let token = bearer_token(request.headers())?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[state.config.jwt_audience.clone()]);
    validation.set_issuer(&[state.config.jwt_issuer.clone()]);
    validation.leeway = 30;

    let decoded = decode::<CapabilityClaims>(
        &token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|e| AppError::Unauthorized(format!("invalid token: {e}")))?;

    if decoded.claims.bindings.mtls_subject != mtls_subject {
        return Err(AppError::Forbidden(
            "capability binding mismatch for mTLS subject".to_string(),
        ));
    }

    let row = sqlx::query(
        r#"
        SELECT jti, revoked_at, expires_at
        FROM capability_tokens
        WHERE jti = ?1
        "#,
    )
    .bind(decoded.claims.jti.clone())
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Err(AppError::Unauthorized("unknown capability token".to_string()));
    };

    let revoked_at: Option<chrono::DateTime<Utc>> = row.try_get("revoked_at")?;
    let expires_at: chrono::DateTime<Utc> = row.try_get("expires_at")?;

    if revoked_at.is_some() {
        return Err(AppError::Unauthorized("capability token revoked".to_string()));
    }

    if expires_at < Utc::now() {
        return Err(AppError::Unauthorized("capability token expired".to_string()));
    }

    request.extensions_mut().insert(AuthContext {
        claims: decoded.claims,
        mtls_subject,
    });

    Ok(next.run(request).await)
}

pub fn issue_capability_token(claims: &CapabilityClaims, jwt_secret: &str) -> Result<String, AppError> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::internal(format!("failed to sign capability token: {e}")))
}

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
    if auth.is_admin() {
        return Ok(());
    }

    if auth.claims.task_id.as_deref() != Some(task_id) {
        return Err(AppError::Forbidden(
            "capability token does not grant this task".to_string(),
        ));
    }

    Ok(())
}

pub fn ensure_ops_subset(auth: &AuthContext, operations: &[String]) -> Result<(), AppError> {
    if auth.is_admin() {
        return Ok(());
    }

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

pub fn ensure_scopes_subset(auth: &AuthContext, scope_pairs: &[(String, String)]) -> Result<(), AppError> {
    if auth.is_admin() {
        return Ok(());
    }

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
