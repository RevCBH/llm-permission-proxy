use std::collections::{BTreeMap, HashSet};

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, patch, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Acquire, Row, Sqlite, Transaction};

use crate::{
    auth::{
        AuthContext, capability_auth_middleware, ensure_ops_subset, ensure_scopes_subset,
        ensure_task_access, extract_mtls_subject, issue_capability_token, make_capability_claims,
    },
    callbacks::enqueue_callback_event,
    db::{new_id, random_token, sha256_hex, sha256_hex_bytes},
    error::AppError,
    models::{
        AgentPermissionItem, AgentPermissionsResponse, ApplyOperation, ApplyPendingResponse,
        ApplyRequest, ApplySuccessResponse, ApprovalStatusResponse, ApproverCredentialItem,
        ApproverCredentialsResponse, CallbackRegistrationInput, ContinueApplyRequest,
        CreateApprovalRequest, CreateApprovalResponse, CreateTaskRequest, CreateTaskResponse,
        DiscordApprovalMessageResponse, OperationExecutionResult, PatchAgentPermissionsRequest,
        PermissionCheck, PermissionGap, PermissionLevel, PermissionTuple, ResourceScope, RiskTier,
        TaskResponse, UpsertApproverCredentialRequest, WebAuthnAllowCredential,
        WebAuthnOptionsResponse, WebAuthnVerifyRequest, WebAuthnVerifyResponse,
    },
    policy::operation_catalog_entry,
    state::AppState,
    webauthn::verify_client_data_json,
};

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/v1/tasks/:task_id", get(get_task))
        .route("/v1/tasks/:task_id/plan", post(plan_task))
        .route("/v1/tasks/:task_id/apply", post(apply_task))
        .route("/v1/tasks/:task_id/apply/continue", post(continue_apply_task))
        .route("/v1/tasks/:task_id/approval-status", get(get_approval_status))
        .route("/v1/tasks/:task_id/approve", post(create_approval_for_task))
        .route(
            "/v1/tasks/:task_id/approve/discord-message",
            get(get_discord_approval_message),
        )
        .route("/v1/tasks/:task_id/close", post(close_task))
        .route("/v1/tasks/:task_id/dns/create", post(dns_create))
        .route("/v1/tasks/:task_id/cache/purge", post(cache_purge))
        .route("/v1/tasks/:task_id/workers/deploy", post(workers_deploy))
        .route("/v1/agents/:agent_id/permissions", get(get_agent_permissions))
        .route("/v1/agents/:agent_id/permissions", patch(patch_agent_permissions))
        .route(
            "/v1/approvers/:approver_principal/credentials",
            get(get_approver_credentials),
        )
        .route(
            "/v1/approvers/:approver_principal/credentials",
            post(upsert_approver_credential),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            capability_auth_middleware,
        ));

    Router::new()
        .route("/v1/healthz", get(healthz))
        .route("/v1/readyz", get(readyz))
        .route("/v1/tasks", post(create_task))
        .route("/v1/approve/:approval_nonce", get(approval_page))
        .route("/v1/approve/:approval_nonce/options", get(approval_options))
        .route("/v1/approve/:approval_nonce/verify", post(approval_verify))
        .merge(protected)
        .with_state(state)
}

async fn healthz() -> Json<Value> {
    Json(json!({"ok": true}))
}

async fn readyz(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    sqlx::query("SELECT 1").execute(&state.db).await?;
    Ok(Json(json!({"ready": true})))
}

async fn create_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateTaskRequest>,
) -> Result<(StatusCode, Json<CreateTaskResponse>), AppError> {
    if payload.task_name.trim().is_empty() {
        return Err(AppError::BadRequest("task_name is required".to_string()));
    }

    if payload.operations.is_empty() {
        return Err(AppError::BadRequest(
            "at least one operation template is required".to_string(),
        ));
    }

    let mtls_subject = extract_mtls_subject(&headers)?;
    let agent_id = headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::Unauthorized("missing x-agent-id".to_string()))?
        .to_string();

    let task_id = new_id("task");
    let now = Utc::now();
    let expires_in = payload.expires_in_seconds.unwrap_or(300).clamp(60, 3600);

    let mut tx = state.db.begin().await?;

    sqlx::query(
        r#"
        INSERT INTO tasks (id, task_name, status, apply_state, callback_id, state_json, created_at, updated_at)
        VALUES (?1, ?2, 'open', 'idle', ?3, ?4, ?5, ?5)
        "#,
    )
    .bind(task_id.clone())
    .bind(payload.task_name.clone())
    .bind(Option::<String>::None)
    .bind(json!({"source": "api"}).to_string())
    .bind(now)
    .execute(&mut *tx)
    .await?;

    let mut allowed_ops = HashSet::new();
    let mut scopes = HashSet::new();

    for operation in &payload.operations {
        let entry = operation_catalog_entry(&operation.operation_id).ok_or_else(|| {
            AppError::BadRequest(format!("unknown operation_id: {}", operation.operation_id))
        })?;

        let required_level = operation.required_level.unwrap_or(entry.required_level);
        let risk_tier = operation.risk_tier.unwrap_or(entry.risk_tier);

        sqlx::query(
            r#"
            INSERT INTO task_operations (
              id,
              task_id,
              operation_id,
              scope_type,
              scope_id,
              required_level,
              risk_tier,
              created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
        )
        .bind(new_id("top"))
        .bind(task_id.clone())
        .bind(operation.operation_id.clone())
        .bind(operation.scope_type.clone())
        .bind(operation.scope_id.clone())
        .bind(permission_level_to_str(required_level))
        .bind(risk_tier_to_str(risk_tier))
        .bind(now)
        .execute(&mut *tx)
        .await?;

        allowed_ops.insert(operation.operation_id.clone());
        scopes.insert((operation.scope_type.clone(), operation.scope_id.clone()));
    }

    let permission_snapshot = fetch_agent_permissions_raw(&mut tx, &agent_id).await?;
    let perms_rev = bump_or_get_agent_permission_version(&mut tx, &agent_id, false).await?;

    sqlx::query(
        r#"
        INSERT INTO task_permission_snapshot (
          id,
          task_id,
          agent_id,
          granted_permissions_json,
          snapshot_version,
          snapshot_at,
          snapshot_ttl_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )
    .bind(new_id("tps"))
    .bind(task_id.clone())
    .bind(agent_id.clone())
    .bind(permission_snapshot.to_string())
    .bind(perms_rev)
    .bind(now)
    .bind(now + Duration::seconds(expires_in))
    .execute(&mut *tx)
    .await?;

    let jti = new_id("cap");
    let claims = make_capability_claims(
        &state.config.jwt_issuer,
        &state.config.jwt_audience,
        &agent_id,
        Some(task_id.clone()),
        jti.clone(),
        expires_in,
        mtls_subject.clone(),
        allowed_ops.into_iter().collect(),
        scopes
            .into_iter()
            .map(|(kind, id)| ResourceScope { kind, id })
            .collect(),
        perms_rev,
    );

    let token = issue_capability_token(&claims, &state.config.jwt_secret)?;

    sqlx::query(
        r#"
        INSERT INTO capability_tokens (
          jti,
          task_id,
          agent_id,
          mtls_subject,
          aud,
          iss,
          allowed_ops_json,
          resource_scopes_json,
          expires_at,
          revoked_at,
          rev,
          created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11)
        "#,
    )
    .bind(jti)
    .bind(task_id.clone())
    .bind(agent_id.clone())
    .bind(mtls_subject)
    .bind(state.config.jwt_audience.clone())
    .bind(state.config.jwt_issuer.clone())
    .bind(serde_json::to_string(&claims.allowed_ops).map_err(AppError::internal)?)
    .bind(serde_json::to_string(&claims.resource_scopes).map_err(AppError::internal)?)
    .bind(chrono::DateTime::from_timestamp(claims.exp as i64, 0).ok_or_else(|| {
        AppError::internal("failed to construct capability expiry timestamp")
    })?)
    .bind(perms_rev)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateTaskResponse {
            task_id,
            status: "open".to_string(),
            capability_token: token,
            capability_ttl_seconds: expires_in,
            callback_id,
        }),
    ))
}

async fn get_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(task_id): Path<String>,
) -> Result<Json<TaskResponse>, AppError> {
    ensure_task_access(&auth, &task_id)?;

    let row = sqlx::query(
        r#"
        SELECT id, task_name, status, apply_state, callback_id, created_at, updated_at
        FROM tasks
        WHERE id = ?1
        "#,
    )
    .bind(task_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("task not found".to_string()))?;

    Ok(Json(TaskResponse {
        task_id: row.try_get("id")?,
        task_name: row.try_get("task_name")?,
        status: row.try_get("status")?,
        apply_state: row.try_get("apply_state")?,
        callback_id: row.try_get("callback_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    }))
}

async fn plan_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(task_id): Path<String>,
    Json(payload): Json<ApplyRequest>,
) -> Result<Json<Value>, AppError> {
    ensure_task_access(&auth, &task_id)?;
    validate_task_operation_allowlist(&state, &task_id, &payload.operations).await?;

    let op_ids: Vec<String> = payload.operations.iter().map(|o| o.operation_id.clone()).collect();
    ensure_ops_subset(&auth, &op_ids)?;
    ensure_scopes_subset(
        &auth,
        &payload
            .operations
            .iter()
            .map(|o| (o.scope_type.clone(), o.scope_id.clone()))
            .collect::<Vec<_>>(),
    )?;

    let (permission_check, requires_approval) =
        evaluate_permissions(&state, &auth.claims.agent_id, &task_id, &payload.operations).await?;

    Ok(Json(json!({
        "task_id": task_id,
        "requires_approval": requires_approval,
        "permission_check": permission_check,
        "planned_diff": {
          "operations": payload.operations,
        }
    })))
}

async fn apply_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ApplyRequest>,
) -> Result<Response, AppError> {
    ensure_task_access(&auth, &task_id)?;

    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::BadRequest("Idempotency-Key header is required".to_string()))?
        .to_string();

    if let Some(callback) = payload.callback.as_ref() {
        upsert_callback_for_task(&state, &task_id, callback).await?;
    }

    match run_apply_flow(
        &state,
        &auth,
        &task_id,
        &idempotency_key,
        payload.operations,
        None,
    )
    .await?
    {
        ApplyFlowOutcome::Pending(body) => Ok((StatusCode::ACCEPTED, Json(json!(body))).into_response()),
        ApplyFlowOutcome::Success(body) => Ok((StatusCode::OK, Json(json!(body))).into_response()),
    }
}

async fn continue_apply_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ContinueApplyRequest>,
) -> Result<Response, AppError> {
    ensure_task_access(&auth, &task_id)?;

    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::BadRequest("Idempotency-Key header is required".to_string()))?
        .to_string();

    match run_continue_flow(&state, &auth, &task_id, &idempotency_key, &payload.resume_token).await? {
        ApplyFlowOutcome::Pending(body) => Ok((StatusCode::ACCEPTED, Json(json!(body))).into_response()),
        ApplyFlowOutcome::Success(body) => Ok((StatusCode::OK, Json(json!(body))).into_response()),
    }
}

async fn create_approval_for_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(task_id): Path<String>,
    Json(payload): Json<CreateApprovalRequest>,
) -> Result<(StatusCode, Json<CreateApprovalResponse>), AppError> {
    ensure_task_access(&auth, &task_id)?;

    let approval = create_or_get_pending_approval(
        &state,
        &task_id,
        "manual",
        PermissionCheck {
            requested: vec![],
            pre_approved: vec![],
            missing: vec![],
        },
        payload
            .approver_principal
            .unwrap_or_else(|| "default".to_string()),
    )
    .await?;

    Ok((StatusCode::CREATED, Json(approval)))
}

async fn get_discord_approval_message(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(task_id): Path<String>,
) -> Result<Json<DiscordApprovalMessageResponse>, AppError> {
    ensure_task_access(&auth, &task_id)?;

    let row = sqlx::query(
        r#"
        SELECT approval_id, expires_at, nonce_plain
        FROM approvals
        WHERE task_id = ?1
          AND state = 'pending'
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(task_id.clone())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("no pending approval request".to_string()))?;

    let approval_id: String = row.try_get("approval_id")?;
    let expires_at: chrono::DateTime<Utc> = row.try_get("expires_at")?;
    let nonce_plain: String = row.try_get("nonce_plain")?;

    let expires_in = (expires_at - Utc::now()).num_seconds().max(0);

    Ok(Json(DiscordApprovalMessageResponse {
        approval_id,
        button_text: "Approve".to_string(),
        approver_summary: "Passkey approval required".to_string(),
        approve_url: format!("{}/v1/approve/{}", state.config.base_url, nonce_plain),
        expires_in_seconds: expires_in,
    }))
}

async fn get_approval_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(task_id): Path<String>,
) -> Result<Json<ApprovalStatusResponse>, AppError> {
    ensure_task_access(&auth, &task_id)?;

    let row = sqlx::query(
        r#"
        SELECT approval_id, state, task_id, operation_fingerprint, created_at, expires_at, approved_at, denied_reason
        FROM approvals
        WHERE task_id = ?1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(task_id.clone())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("approval not found for task".to_string()))?;

    let mut state_value: String = row.try_get("state")?;
    let expires_at: chrono::DateTime<Utc> = row.try_get("expires_at")?;

    if state_value == "pending" && expires_at < Utc::now() {
        let approval_id: String = row.try_get("approval_id")?;
        sqlx::query(
            r#"
            UPDATE approvals
            SET state = 'expired', updated_at = ?1
            WHERE approval_id = ?2
            "#,
        )
        .bind(Utc::now())
        .bind(approval_id.clone())
        .execute(&state.db)
        .await?;
        state_value = "expired".to_string();

        enqueue_callback_event(
            &state,
            &task_id,
            "approval.expired",
            Some(approval_id),
            None,
            json!({"reason": "approval status check detected expiry"}),
        )
        .await?;
    }

    Ok(Json(ApprovalStatusResponse {
        approval_id: row.try_get("approval_id")?,
        state: state_value,
        task_id: row.try_get("task_id")?,
        operation_fingerprint: row.try_get("operation_fingerprint")?,
        created_at: row.try_get("created_at")?,
        expires_at,
        approved_at: row.try_get("approved_at")?,
        denied_reason: row.try_get("denied_reason")?,
    }))
}

#[derive(Debug, Deserialize)]
struct DnsCreateRequest {
    scope_id: String,
    name: String,
    record_type: String,
    content: String,
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    proxied: Option<bool>,
}

async fn dns_create(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DnsCreateRequest>,
) -> Result<Response, AppError> {
    let apply_req = ApplyRequest {
        operations: vec![ApplyOperation {
            operation_id: "dns.record.write".to_string(),
            scope_type: "zone".to_string(),
            scope_id: payload.scope_id,
            params: json!({
                "action": "create",
                "name": payload.name,
                "record_type": payload.record_type,
                "content": payload.content,
                "ttl": payload.ttl.unwrap_or(300),
                "proxied": payload.proxied.unwrap_or(false)
            }),
        }],
        callback: None,
    };

    apply_task(State(state), Extension(auth), Path(task_id), headers, Json(apply_req)).await
}

#[derive(Debug, Deserialize)]
struct CachePurgeRequest {
    scope_id: String,
    #[serde(default)]
    purge_everything: Option<bool>,
    #[serde(default)]
    files: Option<Vec<String>>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

async fn cache_purge(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<CachePurgeRequest>,
) -> Result<Response, AppError> {
    let apply_req = ApplyRequest {
        operations: vec![ApplyOperation {
            operation_id: "cache.purge.execute".to_string(),
            scope_type: "zone".to_string(),
            scope_id: payload.scope_id,
            params: json!({
                "purge_everything": payload.purge_everything.unwrap_or(false),
                "files": payload.files,
                "tags": payload.tags,
            }),
        }],
        callback: None,
    };

    apply_task(State(state), Extension(auth), Path(task_id), headers, Json(apply_req)).await
}

#[derive(Debug, Deserialize)]
struct WorkersDeployRequest {
    scope_id: String,
    script_name: String,
    script: String,
}

async fn workers_deploy(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<WorkersDeployRequest>,
) -> Result<Response, AppError> {
    let apply_req = ApplyRequest {
        operations: vec![ApplyOperation {
            operation_id: "workers.deploy.write".to_string(),
            scope_type: "account".to_string(),
            scope_id: payload.scope_id,
            params: json!({
                "script_name": payload.script_name,
                "script": payload.script,
            }),
        }],
        callback: None,
    };

    apply_task(State(state), Extension(auth), Path(task_id), headers, Json(apply_req)).await
}

async fn close_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(task_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_task_access(&auth, &task_id)?;

    let mut tx = state.db.begin().await?;

    sqlx::query(
        r#"
        UPDATE tasks
        SET status = 'closed', apply_state = 'closed', updated_at = ?1
        WHERE id = ?2
        "#,
    )
    .bind(Utc::now())
    .bind(task_id.clone())
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE capability_tokens
        SET revoked_at = ?1
        WHERE task_id = ?2
          AND revoked_at IS NULL
        "#,
    )
    .bind(Utc::now())
    .bind(task_id.clone())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(json!({"task_id": task_id, "status": "closed"})))
}

async fn get_agent_permissions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentPermissionsResponse>, AppError> {
    if !auth.is_admin() && auth.claims.agent_id != agent_id {
        return Err(AppError::Forbidden(
            "cannot access permissions for another agent".to_string(),
        ));
    }

    let rows = sqlx::query(
        r#"
        SELECT operation_id, scope_type, scope_id, granted_level, expires_at
        FROM agent_permissions
        WHERE agent_id = ?1
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > ?2)
        ORDER BY operation_id, scope_type, scope_id
        "#,
    )
    .bind(agent_id.clone())
    .bind(Utc::now())
    .fetch_all(&state.db)
    .await?;

    let mut permissions = Vec::with_capacity(rows.len());
    for row in rows {
        permissions.push(AgentPermissionItem {
            operation_id: row.try_get("operation_id")?,
            scope_type: row.try_get("scope_type")?,
            scope_id: row.try_get("scope_id")?,
            granted_level: str_to_permission_level(&row.try_get::<String, _>("granted_level")?)?,
            expires_at: row.try_get("expires_at")?,
        });
    }

    Ok(Json(AgentPermissionsResponse {
        agent_id,
        permissions,
    }))
}

async fn patch_agent_permissions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(agent_id): Path<String>,
    Json(payload): Json<PatchAgentPermissionsRequest>,
) -> Result<Json<AgentPermissionsResponse>, AppError> {
    if !auth.is_admin() {
        return Err(AppError::Forbidden(
            "admin capability required for permission updates".to_string(),
        ));
    }

    let mut tx = state.db.begin().await?;

    sqlx::query(
        r#"
        UPDATE agent_permissions
        SET revoked_at = ?1
        WHERE agent_id = ?2
          AND revoked_at IS NULL
        "#,
    )
    .bind(Utc::now())
    .bind(agent_id.clone())
    .execute(&mut *tx)
    .await?;

    for permission in &payload.permissions {
        operation_catalog_entry(&permission.operation_id).ok_or_else(|| {
            AppError::BadRequest(format!("unknown operation_id: {}", permission.operation_id))
        })?;

        sqlx::query(
            r#"
            INSERT INTO agent_permissions (
              id,
              agent_id,
              operation_id,
              scope_type,
              scope_id,
              granted_level,
              source,
              not_before,
              expires_at,
              revoked_at,
              created_at,
              updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'manual', ?7, ?8, NULL, ?7, ?7)
            "#,
        )
        .bind(new_id("ap"))
        .bind(agent_id.clone())
        .bind(permission.operation_id.clone())
        .bind(permission.scope_type.clone())
        .bind(permission.scope_id.clone())
        .bind(permission_level_to_str(permission.granted_level))
        .bind(Utc::now())
        .bind(permission.expires_at)
        .execute(&mut *tx)
        .await?;
    }

    bump_or_get_agent_permission_version(&mut tx, &agent_id, true).await?;

    tx.commit().await?;

    get_agent_permissions(State(state), Extension(auth), Path(agent_id)).await
}

async fn get_approver_credentials(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(approver_principal): Path<String>,
) -> Result<Json<ApproverCredentialsResponse>, AppError> {
    if !auth.is_admin() {
        return Err(AppError::Forbidden(
            "admin capability required for approver credential access".to_string(),
        ));
    }

    let rows = sqlx::query(
        r#"
        SELECT credential_id, status
        FROM approver_credentials
        WHERE approver_principal = ?1
        ORDER BY created_at DESC
        "#,
    )
    .bind(approver_principal.clone())
    .fetch_all(&state.db)
    .await?;

    let mut credentials = Vec::new();
    for row in rows {
        credentials.push(ApproverCredentialItem {
            credential_id: row.try_get("credential_id")?,
            status: row.try_get("status")?,
        });
    }

    Ok(Json(ApproverCredentialsResponse {
        approver_principal,
        credentials,
    }))
}

async fn upsert_approver_credential(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(approver_principal): Path<String>,
    Json(payload): Json<UpsertApproverCredentialRequest>,
) -> Result<Json<ApproverCredentialsResponse>, AppError> {
    if !auth.is_admin() {
        return Err(AppError::Forbidden(
            "admin capability required for approver credential updates".to_string(),
        ));
    }

    if payload.credential_id.trim().is_empty() {
        return Err(AppError::BadRequest("credential_id is required".to_string()));
    }

    if payload.status != "active" && payload.status != "inactive" {
        return Err(AppError::BadRequest(
            "status must be active or inactive".to_string(),
        ));
    }

    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO approver_credentials (
          id,
          approver_principal,
          credential_id,
          status,
          created_at,
          updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)
        ON CONFLICT(approver_principal, credential_id)
        DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at
        "#,
    )
    .bind(new_id("ac"))
    .bind(approver_principal.clone())
    .bind(payload.credential_id)
    .bind(payload.status)
    .bind(now)
    .execute(&state.db)
    .await?;

    get_approver_credentials(State(state), Extension(auth), Path(approver_principal)).await
}

async fn approval_page(
    State(state): State<AppState>,
    Path(approval_nonce): Path<String>,
) -> Result<Html<String>, AppError> {
    let nonce_hash = sha256_hex(&approval_nonce);

    let row = sqlx::query(
        r#"
        SELECT approval_id, state, expires_at
        FROM approvals
        WHERE nonce_hash = ?1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(nonce_hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("approval link not found".to_string()))?;

    let state_value: String = row.try_get("state")?;
    let expires_at: chrono::DateTime<Utc> = row.try_get("expires_at")?;

    if state_value != "pending" || expires_at < Utc::now() {
        return Err(AppError::Gone("approval link expired".to_string()));
    }

    let html = format!(
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Approval</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2rem; max-width: 720px; }}
    .status {{ margin-top: 1rem; font-weight: 600; }}
    button {{ padding: 0.7rem 1rem; border-radius: 8px; border: 1px solid #111; background: #111; color: #fff; cursor: pointer; }}
  </style>
</head>
<body>
  <h1>Approve Action</h1>
  <p>This action requires passkey verification.</p>
  <button id="approve">Approve with Passkey</button>
  <div class="status" id="status"></div>
  <script>
    function b64ToArrayBuffer(base64url) {{
      const padding = '='.repeat((4 - base64url.length % 4) % 4);
      const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
      const raw = atob(base64);
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
      return bytes.buffer;
    }}

    function arrayBufferToB64(buf) {{
      const bytes = new Uint8Array(buf);
      let str = '';
      for (const b of bytes) str += String.fromCharCode(b);
      return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }}

    async function run() {{
      const status = document.getElementById('status');
      status.textContent = 'Requesting challenge...';

      const optionsRes = await fetch('/v1/approve/{0}/options');
      if (!optionsRes.ok) {{
        status.textContent = 'Could not load challenge.';
        return;
      }}

      const options = await optionsRes.json();
      const publicKey = {{
        challenge: b64ToArrayBuffer(options.challenge),
        timeout: options.timeout,
        rpId: options.rp_id,
        userVerification: options.user_verification,
        allowCredentials: options.allow_credentials.map((c) => ({{
          id: b64ToArrayBuffer(c.id),
          type: c.kind
        }}))
      }};

      status.textContent = 'Waiting for passkey...';
      const assertion = await navigator.credentials.get({{ publicKey }});
      const response = assertion.response;

      const body = {{
        credential_id: arrayBufferToB64(assertion.rawId),
        client_data_json: arrayBufferToB64(response.clientDataJSON),
        authenticator_data: arrayBufferToB64(response.authenticatorData),
        signature: arrayBufferToB64(response.signature),
        user_handle: response.userHandle ? arrayBufferToB64(response.userHandle) : null
      }};

      const verifyRes = await fetch('/v1/approve/{0}/verify', {{
        method: 'POST',
        headers: {{ 'content-type': 'application/json' }},
        body: JSON.stringify(body)
      }});

      if (verifyRes.ok) {{
        status.textContent = 'Approved. You can close this tab.';
      }} else {{
        const err = await verifyRes.json().catch(() => ({{message:'Verification failed'}}));
        status.textContent = `Verification failed: ${{err.message || 'unknown error'}}`;
      }}
    }}

    document.getElementById('approve').addEventListener('click', () => run().catch((err) => {{
      document.getElementById('status').textContent = `Error: ${{err.message}}`;
    }}));
  </script>
</body>
</html>"#,
        approval_nonce
    );

    Ok(Html(html))
}

async fn approval_options(
    State(state): State<AppState>,
    Path(approval_nonce): Path<String>,
) -> Result<Json<WebAuthnOptionsResponse>, AppError> {
    let nonce_hash = sha256_hex(&approval_nonce);

    let mut tx = state.db.begin().await?;

    let row = sqlx::query(
        r#"
        SELECT id, approval_id, approver_principal, state, expires_at
        FROM approvals
        WHERE nonce_hash = ?1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(nonce_hash)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("approval not found".to_string()))?;

    let approval_state: String = row.try_get("state")?;
    let expires_at: chrono::DateTime<Utc> = row.try_get("expires_at")?;
    if approval_state != "pending" || expires_at < Utc::now() {
        return Err(AppError::Gone("approval expired".to_string()));
    }

    let approval_id: String = row.try_get("approval_id")?;
    let approver_principal: String = row.try_get("approver_principal")?;

    let credential_rows = sqlx::query(
        r#"
        SELECT credential_id
        FROM approver_credentials
        WHERE approver_principal = ?1
          AND status = 'active'
        "#,
    )
    .bind(approver_principal)
    .fetch_all(&mut *tx)
    .await?;

    if credential_rows.is_empty() {
        return Err(AppError::BadRequest(
            "no active passkey credential configured for approver".to_string(),
        ));
    }

    let challenge = random_token(32);
    let challenge_hash = sha256_hex(&challenge);

    sqlx::query(
        r#"
        INSERT INTO webauthn_challenges (
          id,
          approval_id,
          challenge,
          challenge_hash,
          created_at,
          expires_at,
          used_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
        "#,
    )
    .bind(new_id("wch"))
    .bind(approval_id)
    .bind(challenge.clone())
    .bind(challenge_hash)
    .bind(Utc::now())
    .bind(Utc::now() + Duration::seconds(state.config.approval_nonce_ttl_seconds))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let allow_credentials = credential_rows
        .iter()
        .filter_map(|row| row.try_get::<String, _>("credential_id").ok())
        .map(|id| WebAuthnAllowCredential {
            id,
            kind: "public-key".to_string(),
        })
        .collect();

    Ok(Json(WebAuthnOptionsResponse {
        challenge,
        timeout: 60_000,
        rp_id: state.config.webauthn_rp_id.clone(),
        user_verification: "required".to_string(),
        allow_credentials,
    }))
}

async fn approval_verify(
    State(state): State<AppState>,
    Path(approval_nonce): Path<String>,
    Json(payload): Json<WebAuthnVerifyRequest>,
) -> Result<Json<WebAuthnVerifyResponse>, AppError> {
    if payload.authenticator_data.is_empty() || payload.signature.is_empty() {
        return Err(AppError::BadRequest(
            "missing authenticator assertion fields".to_string(),
        ));
    }

    let nonce_hash = sha256_hex(&approval_nonce);
    let mut tx = state.db.begin().await?;

    let approval_row = sqlx::query(
        r#"
        SELECT id, approval_id, task_id, state, expires_at, approver_principal
        FROM approvals
        WHERE nonce_hash = ?1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(nonce_hash)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("approval not found".to_string()))?;

    let approval_db_id: String = approval_row.try_get("id")?;
    let approval_id: String = approval_row.try_get("approval_id")?;
    let task_id: String = approval_row.try_get("task_id")?;
    let approval_state: String = approval_row.try_get("state")?;
    let expires_at: chrono::DateTime<Utc> = approval_row.try_get("expires_at")?;
    let approver_principal: String = approval_row.try_get("approver_principal")?;

    if approval_state != "pending" || expires_at < Utc::now() {
        return Err(AppError::Gone("approval is no longer pending".to_string()));
    }

    let challenge_row = sqlx::query(
        r#"
        SELECT id, challenge, expires_at
        FROM webauthn_challenges
        WHERE approval_id = ?1
          AND used_at IS NULL
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(approval_id.clone())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::BadRequest("missing active challenge".to_string()))?;

    let challenge_id: String = challenge_row.try_get("id")?;
    let challenge: String = challenge_row.try_get("challenge")?;
    let challenge_expires_at: chrono::DateTime<Utc> = challenge_row.try_get("expires_at")?;

    if challenge_expires_at < Utc::now() {
        return Err(AppError::Gone("challenge expired".to_string()));
    }

    let credential_exists = sqlx::query(
        r#"
        SELECT id
        FROM approver_credentials
        WHERE approver_principal = ?1
          AND credential_id = ?2
          AND status = 'active'
        LIMIT 1
        "#,
    )
    .bind(approver_principal)
    .bind(payload.credential_id.clone())
    .fetch_optional(&mut *tx)
    .await?
    .is_some();

    if !credential_exists {
        return Err(AppError::Forbidden(
            "credential is not registered for approver".to_string(),
        ));
    }

    verify_client_data_json(
        &payload.client_data_json,
        &challenge,
        &state.config.webauthn_origin,
    )?;

    sqlx::query(
        r#"
        UPDATE webauthn_challenges
        SET used_at = ?1
        WHERE id = ?2
        "#,
    )
    .bind(Utc::now())
    .bind(challenge_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE approvals
        SET state = 'approved',
            approved_at = ?1,
            approved_by = ?2,
            updated_at = ?1
        WHERE id = ?3
        "#,
    )
    .bind(Utc::now())
    .bind(payload.credential_id.clone())
    .bind(approval_db_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE tasks
        SET status = 'approved',
            apply_state = 'ready',
            updated_at = ?1
        WHERE id = ?2
        "#,
    )
    .bind(Utc::now())
    .bind(task_id.clone())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    enqueue_callback_event(
        &state,
        &task_id,
        "approval.approved",
        Some(approval_id.clone()),
        None,
        json!({"approved_by": payload.credential_id}),
    )
    .await?;

    Ok(Json(WebAuthnVerifyResponse {
        approval_id,
        status: "approved".to_string(),
        task_id,
    }))
}

enum ApplyFlowOutcome {
    Pending(ApplyPendingResponse),
    Success(ApplySuccessResponse),
}

async fn run_apply_flow(
    state: &AppState,
    auth: &AuthContext,
    task_id: &str,
    idempotency_key: &str,
    operations: Vec<ApplyOperation>,
    expected_resume_token: Option<&str>,
) -> Result<ApplyFlowOutcome, AppError> {
    if operations.is_empty() {
        return Err(AppError::BadRequest("operations cannot be empty".to_string()));
    }

    validate_task_operation_allowlist(state, task_id, &operations).await?;
    validate_operation_params(&operations)?;

    let op_ids: Vec<String> = operations.iter().map(|op| op.operation_id.clone()).collect();
    let scope_pairs: Vec<(String, String)> = operations
        .iter()
        .map(|op| (op.scope_type.clone(), op.scope_id.clone()))
        .collect();

    ensure_ops_subset(auth, &op_ids)?;
    ensure_scopes_subset(auth, &scope_pairs)?;

    let perms_rev = current_agent_permission_version(state, &auth.claims.agent_id).await?;
    if auth.claims.perms_rev < perms_rev {
        return Err(AppError::Unauthorized(
            "capability token has stale permission revision".to_string(),
        ));
    }

    let request_json = serde_json::to_value(&operations).map_err(AppError::internal)?;
    let fingerprint = canonical_fingerprint(&request_json)?;
    let key_hash = sha256_hex(idempotency_key);

    let mut tx = state.db.begin().await?;

    let existing_row = sqlx::query(
        r#"
        SELECT id, status, operation_fingerprint, response_json, approval_id, request_json, http_status
        FROM idempotency_records
        WHERE task_id = ?1
          AND idempotency_key_hash = ?2
        LIMIT 1
        "#,
    )
    .bind(task_id)
    .bind(key_hash.clone())
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(row) = existing_row {
        let existing_status: String = row.try_get("status")?;
        let existing_fingerprint: String = row.try_get("operation_fingerprint")?;
        if existing_fingerprint != fingerprint {
            return Err(AppError::Conflict(
                "idempotency key reused with different payload".to_string(),
            ));
        }

        if existing_status == "completed" || existing_status == "failed" {
            let response_json: String = row.try_get("response_json")?;
            let body: ApplySuccessResponse = serde_json::from_str(&response_json).map_err(AppError::internal)?;
            return Ok(ApplyFlowOutcome::Success(body));
        }

        if existing_status == "pending_approval" {
            let approval_id: String = row.try_get("approval_id")?;
            let approval = fetch_approval_by_id(&mut tx, &approval_id).await?;

            if approval.state == "approved" {
                if let Some(token) = expected_resume_token {
                    let token_hash = sha256_hex(token);
                    if approval.resume_token_hash != token_hash {
                        return Err(AppError::Forbidden("resume token mismatch".to_string()));
                    }
                }

                sqlx::query(
                    r#"
                    UPDATE idempotency_records
                    SET status = 'applying', updated_at = ?1
                    WHERE id = ?2
                      AND status = 'pending_approval'
                    "#,
                )
                .bind(Utc::now())
                .bind(row.try_get::<String, _>("id")?)
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;

                let request_json_str: String = row.try_get("request_json")?;
                let replay_ops: Vec<ApplyOperation> =
                    serde_json::from_str(&request_json_str).map_err(AppError::internal)?;
                return execute_and_finalize(
                    state,
                    task_id,
                    idempotency_key,
                    key_hash,
                    replay_ops,
                    Some(approval_id),
                )
                .await;
            }

            if approval.state == "denied" {
                return Err(AppError::Conflict("approval denied".to_string()));
            }

            if approval.state == "expired" {
                return Err(AppError::Gone("approval expired".to_string()));
            }

            let response_json: String = row.try_get("response_json")?;
            let body: ApplyPendingResponse = serde_json::from_str(&response_json).map_err(AppError::internal)?;
            return Ok(ApplyFlowOutcome::Pending(body));
        }

        if existing_status == "applying" {
            return Ok(ApplyFlowOutcome::Pending(ApplyPendingResponse {
                status: "in_progress".to_string(),
                task_id: task_id.to_string(),
                apply_state: "applying".to_string(),
                approval_id: "".to_string(),
                approval_status_url: format!("/v1/tasks/{task_id}/approval-status"),
                resume_token: "".to_string(),
                idempotency_key: idempotency_key.to_string(),
                retry_after_seconds: 5,
                callback_id: None,
                permission_check: PermissionCheck {
                    requested: vec![],
                    pre_approved: vec![],
                    missing: vec![],
                },
            }));
        }
    } else {
        sqlx::query(
            r#"
            INSERT INTO idempotency_records (
              id,
              task_id,
              idempotency_key_hash,
              operation_fingerprint,
              status,
              request_json,
              response_json,
              approval_id,
              http_status,
              created_at,
              updated_at,
              expires_at
            ) VALUES (?1, ?2, ?3, ?4, 'evaluating', ?5, NULL, NULL, NULL, ?6, ?6, ?7)
            "#,
        )
        .bind(new_id("idem"))
        .bind(task_id)
        .bind(key_hash.clone())
        .bind(fingerprint.clone())
        .bind(request_json.to_string())
        .bind(Utc::now())
        .bind(Utc::now() + Duration::hours(24))
        .execute(&mut *tx)
        .await?;
    }

    let (permission_check, requires_approval) =
        evaluate_permissions(state, &auth.claims.agent_id, task_id, &operations).await?;

    if requires_approval {
        let approval = create_or_get_pending_approval(
            state,
            task_id,
            &fingerprint,
            permission_check.clone(),
            "default".to_string(),
        )
        .await?;

        let response = ApplyPendingResponse {
            status: "requires_approval".to_string(),
            task_id: task_id.to_string(),
            apply_state: "waiting_approval".to_string(),
            approval_id: approval.approval_id.clone(),
            approval_status_url: approval.approval_status_url.clone(),
            resume_token: approval.resume_token.clone(),
            idempotency_key: idempotency_key.to_string(),
            retry_after_seconds: 30,
            callback_id: approval.callback_id.clone(),
            permission_check,
        };

        sqlx::query(
            r#"
            UPDATE tasks
            SET status = 'requires_approval',
                apply_state = 'waiting_approval',
                updated_at = ?1
            WHERE id = ?2
            "#,
        )
        .bind(Utc::now())
        .bind(task_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            UPDATE idempotency_records
            SET status = 'pending_approval',
                response_json = ?1,
                approval_id = ?2,
                http_status = 202,
                updated_at = ?3
            WHERE task_id = ?4
              AND idempotency_key_hash = ?5
            "#,
        )
        .bind(serde_json::to_string(&response).map_err(AppError::internal)?)
        .bind(response.approval_id.clone())
        .bind(Utc::now())
        .bind(task_id)
        .bind(key_hash)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        enqueue_callback_event(
            state,
            task_id,
            "approval.pending",
            Some(response.approval_id.clone()),
            Some(idempotency_key.to_string()),
            json!({
                "approval_status_url": response.approval_status_url,
                "resume_token": response.resume_token,
                "permission_check": response.permission_check,
            }),
        )
        .await?;

        return Ok(ApplyFlowOutcome::Pending(response));
    }

    sqlx::query(
        r#"
        UPDATE idempotency_records
        SET status = 'applying',
            updated_at = ?1
        WHERE task_id = ?2
          AND idempotency_key_hash = ?3
        "#,
    )
    .bind(Utc::now())
    .bind(task_id)
    .bind(key_hash.clone())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    execute_and_finalize(
        state,
        task_id,
        idempotency_key,
        key_hash,
        operations,
        None,
    )
    .await
}

async fn run_continue_flow(
    state: &AppState,
    auth: &AuthContext,
    task_id: &str,
    idempotency_key: &str,
    resume_token: &str,
) -> Result<ApplyFlowOutcome, AppError> {
    ensure_task_access(auth, task_id)?;

    let key_hash = sha256_hex(idempotency_key);

    let row = sqlx::query(
        r#"
        SELECT status, request_json
        FROM idempotency_records
        WHERE task_id = ?1
          AND idempotency_key_hash = ?2
        LIMIT 1
        "#,
    )
    .bind(task_id)
    .bind(key_hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("idempotency record not found".to_string()))?;

    let status: String = row.try_get("status")?;
    if status != "pending_approval"
        && status != "completed"
        && status != "failed"
        && status != "applying"
    {
        return Err(AppError::Conflict(
            "apply state is not resumable".to_string(),
        ));
    }

    let request_json: String = row.try_get("request_json")?;
    let operations: Vec<ApplyOperation> =
        serde_json::from_str(&request_json).map_err(AppError::internal)?;

    run_apply_flow(
        state,
        auth,
        task_id,
        idempotency_key,
        operations,
        Some(resume_token),
    )
    .await
}

async fn execute_and_finalize(
    state: &AppState,
    task_id: &str,
    idempotency_key: &str,
    key_hash: String,
    operations: Vec<ApplyOperation>,
    approval_id: Option<String>,
) -> Result<ApplyFlowOutcome, AppError> {
    sqlx::query(
        r#"
        UPDATE tasks
        SET status = 'applying',
            apply_state = 'applying',
            updated_at = ?1
        WHERE id = ?2
        "#,
    )
    .bind(Utc::now())
    .bind(task_id)
    .execute(&state.db)
    .await?;

    let execution_id = new_id("exec");
    let mut results: Vec<OperationExecutionResult> = Vec::with_capacity(operations.len());

    for operation in operations {
        let result = state
            .cf_executor
            .execute(
                &operation.operation_id,
                &operation.scope_type,
                &operation.scope_id,
                &operation.params,
            )
            .await?;
        results.push(result);
    }

    let all_success = results.iter().all(|r| r.success);
    let final_status = if all_success { "completed" } else { "failed" };
    let apply_state = if all_success { "completed" } else { "failed" };

    let response = ApplySuccessResponse {
        status: final_status.to_string(),
        task_id: task_id.to_string(),
        apply_state: apply_state.to_string(),
        idempotency_key: idempotency_key.to_string(),
        execution_id,
        results,
    };

    let http_status = if all_success { 200_i64 } else { 409_i64 };

    let mut tx = state.db.begin().await?;

    sqlx::query(
        r#"
        UPDATE tasks
        SET status = ?1,
            apply_state = ?2,
            updated_at = ?3
        WHERE id = ?4
        "#,
    )
    .bind(final_status)
    .bind(apply_state)
    .bind(Utc::now())
    .bind(task_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE idempotency_records
        SET status = ?1,
            response_json = ?2,
            http_status = ?3,
            updated_at = ?4
        WHERE task_id = ?5
          AND idempotency_key_hash = ?6
        "#,
    )
    .bind(final_status)
    .bind(serde_json::to_string(&response).map_err(AppError::internal)?)
    .bind(http_status)
    .bind(Utc::now())
    .bind(task_id)
    .bind(key_hash)
    .execute(&mut *tx)
    .await?;

    if let Some(approval_id) = approval_id {
        sqlx::query(
            r#"
            UPDATE approvals
            SET state = 'consumed',
                consumed_at = ?1,
                updated_at = ?1
            WHERE approval_id = ?2
              AND state = 'approved'
            "#,
        )
        .bind(Utc::now())
        .bind(approval_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    let event_name = if all_success {
        "apply.finished"
    } else {
        "apply.failed"
    };

    enqueue_callback_event(
        state,
        task_id,
        event_name,
        None,
        Some(idempotency_key.to_string()),
        json!({"response": response}),
    )
    .await?;

    Ok(ApplyFlowOutcome::Success(response))
}

async fn validate_task_operation_allowlist(
    state: &AppState,
    task_id: &str,
    operations: &[ApplyOperation],
) -> Result<(), AppError> {
    let rows = sqlx::query(
        r#"
        SELECT operation_id, scope_type, scope_id
        FROM task_operations
        WHERE task_id = ?1
        "#,
    )
    .bind(task_id)
    .fetch_all(&state.db)
    .await?;

    let mut allowed = HashSet::new();
    for row in rows {
        let operation_id: String = row.try_get("operation_id")?;
        let scope_type: String = row.try_get("scope_type")?;
        let scope_id: String = row.try_get("scope_id")?;
        allowed.insert((operation_id, scope_type, scope_id));
    }

    for op in operations {
        if !allowed.contains(&(op.operation_id.clone(), op.scope_type.clone(), op.scope_id.clone())) {
            return Err(AppError::Forbidden(format!(
                "operation {} on {}:{} not in task allowlist",
                op.operation_id, op.scope_type, op.scope_id
            )));
        }
    }

    Ok(())
}

fn validate_operation_params(operations: &[ApplyOperation]) -> Result<(), AppError> {
    for operation in operations {
        let entry = operation_catalog_entry(&operation.operation_id)
            .ok_or_else(|| AppError::BadRequest(format!("unknown operation {}", operation.operation_id)))?;

        if entry.risk_tier == RiskTier::Sensitive {
            // Sensitive operations still proceed through policy checks and approval flow.
        }

        match operation.operation_id.as_str() {
            "dns.record.write" => {
                let action = operation
                    .params
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("create");
                if action == "create" {
                    for key in ["name", "record_type", "content"] {
                        if operation.params.get(key).is_none() {
                            return Err(AppError::BadRequest(format!(
                                "dns create missing {}",
                                key
                            )));
                        }
                    }
                }
                if let Some(ttl) = operation.params.get("ttl").and_then(|v| v.as_i64()) {
                    if !(60..=86400).contains(&ttl) {
                        return Err(AppError::BadRequest("dns ttl must be 60..86400".to_string()));
                    }
                }
            }
            "cache.purge.execute" => {
                let purge_everything = operation
                    .params
                    .get("purge_everything")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let files = operation
                    .params
                    .get("files")
                    .and_then(|v| v.as_array())
                    .map(|v| !v.is_empty())
                    .unwrap_or(false);
                let tags = operation
                    .params
                    .get("tags")
                    .and_then(|v| v.as_array())
                    .map(|v| !v.is_empty())
                    .unwrap_or(false);
                if !(purge_everything || files || tags) {
                    return Err(AppError::BadRequest(
                        "cache purge requires purge_everything or files/tags".to_string(),
                    ));
                }
            }
            "workers.deploy.write" => {
                if operation
                    .params
                    .get("script_name")
                    .and_then(|v| v.as_str())
                    .is_none()
                {
                    return Err(AppError::BadRequest(
                        "workers deploy requires script_name".to_string(),
                    ));
                }
            }
            _ => {}
        }
    }

    Ok(())
}

async fn evaluate_permissions(
    state: &AppState,
    agent_id: &str,
    task_id: &str,
    operations: &[ApplyOperation],
) -> Result<(PermissionCheck, bool), AppError> {
    let mut requested = Vec::new();
    let mut pre_approved = Vec::new();
    let mut missing = Vec::new();
    let mut requires_approval = false;

    for op in operations {
        let entry = operation_catalog_entry(&op.operation_id)
            .ok_or_else(|| AppError::BadRequest(format!("unknown operation {}", op.operation_id)))?;

        let granted = fetch_best_permission_level(
            &state.db,
            agent_id,
            &op.operation_id,
            &op.scope_type,
            &op.scope_id,
        )
        .await?;

        requested.push(PermissionTuple {
            operation_id: op.operation_id.clone(),
            scope_type: op.scope_type.clone(),
            scope_id: op.scope_id.clone(),
            level: entry.required_level,
        });

        if let Some(level) = granted {
            pre_approved.push(PermissionTuple {
                operation_id: op.operation_id.clone(),
                scope_type: op.scope_type.clone(),
                scope_id: op.scope_id.clone(),
                level,
            });
        }

        let insufficient = granted.map(|g| g < entry.required_level).unwrap_or(true);

        if insufficient {
            requires_approval = true;
            missing.push(PermissionGap {
                operation_id: op.operation_id.clone(),
                scope_type: op.scope_type.clone(),
                scope_id: op.scope_id.clone(),
                needed: entry.required_level,
                granted,
            });
        }

        if entry.risk_tier == RiskTier::Sensitive {
            requires_approval = true;
        }
    }

    let permission_check = PermissionCheck {
        requested,
        pre_approved,
        missing,
    };

    sqlx::query(
        r#"
        INSERT INTO permission_evaluations (
          id,
          task_id,
          apply_request_id,
          requested_permissions_json,
          granted_permissions_json,
          missing_permissions_json,
          requires_approval,
          created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
    )
    .bind(new_id("pe"))
    .bind(task_id)
    .bind(new_id("apr"))
    .bind(serde_json::to_string(&permission_check.requested).map_err(AppError::internal)?)
    .bind(serde_json::to_string(&permission_check.pre_approved).map_err(AppError::internal)?)
    .bind(serde_json::to_string(&permission_check.missing).map_err(AppError::internal)?)
    .bind(if requires_approval { 1 } else { 0 })
    .bind(Utc::now())
    .execute(&state.db)
    .await?;

    Ok((permission_check, requires_approval))
}

async fn fetch_best_permission_level(
    db: &sqlx::SqlitePool,
    agent_id: &str,
    operation_id: &str,
    scope_type: &str,
    scope_id: &str,
) -> Result<Option<PermissionLevel>, AppError> {
    let rows = sqlx::query(
        r#"
        SELECT granted_level
        FROM agent_permissions
        WHERE agent_id = ?1
          AND operation_id = ?2
          AND scope_type = ?3
          AND (scope_id = ?4 OR scope_id = '*')
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > ?5)
        "#,
    )
    .bind(agent_id)
    .bind(operation_id)
    .bind(scope_type)
    .bind(scope_id)
    .bind(Utc::now())
    .fetch_all(db)
    .await?;

    let mut best: Option<PermissionLevel> = None;
    for row in rows {
        let level = str_to_permission_level(&row.try_get::<String, _>("granted_level")?)?;
        if best.map(|v| level > v).unwrap_or(true) {
            best = Some(level);
        }
    }

    Ok(best)
}

#[derive(Debug, Clone)]
struct ApprovalRecord {
    approval_id: String,
    state: String,
    resume_token_hash: String,
}

async fn fetch_approval_by_id(
    tx: &mut Transaction<'_, Sqlite>,
    approval_id: &str,
) -> Result<ApprovalRecord, AppError> {
    let row = sqlx::query(
        r#"
        SELECT approval_id, state, resume_token_hash
        FROM approvals
        WHERE approval_id = ?1
        LIMIT 1
        "#,
    )
    .bind(approval_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| AppError::NotFound("approval not found".to_string()))?;

    Ok(ApprovalRecord {
        approval_id: row.try_get("approval_id")?,
        state: row.try_get("state")?,
        resume_token_hash: row.try_get("resume_token_hash")?,
    })
}

#[derive(Debug, Clone, Serialize)]
struct PendingApprovalCreateResult {
    approval_id: String,
    approval_status_url: String,
    resume_token: String,
    callback_id: Option<String>,
}

async fn create_or_get_pending_approval(
    state: &AppState,
    task_id: &str,
    operation_fingerprint: &str,
    permission_check: PermissionCheck,
    approver_principal: String,
) -> Result<PendingApprovalCreateResult, AppError> {
    let mut tx = state.db.begin().await?;

    let existing = sqlx::query(
        r#"
        SELECT approval_id, nonce_plain, resume_token_plain
        FROM approvals
        WHERE task_id = ?1
          AND operation_fingerprint = ?2
          AND state = 'pending'
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(task_id)
    .bind(operation_fingerprint)
    .fetch_optional(&mut *tx)
    .await?;

    let callback_id = sqlx::query("SELECT callback_id FROM tasks WHERE id = ?1")
        .bind(task_id)
        .fetch_optional(&mut *tx)
        .await?
        .and_then(|row| row.try_get::<String, _>("callback_id").ok());

    if let Some(row) = existing {
        let approval_id: String = row.try_get("approval_id")?;
        let resume_token: String = row.try_get("resume_token_plain")?;
        tx.commit().await?;

        return Ok(PendingApprovalCreateResult {
            approval_id,
            approval_status_url: format!("/v1/tasks/{task_id}/approval-status"),
            resume_token,
            callback_id,
        });
    }

    let approval_id = new_id("appr");
    let nonce_plain = random_token(24);
    let resume_token_plain = random_token(24);

    let nonce_hash = sha256_hex(&nonce_plain);
    let resume_token_hash = sha256_hex(&resume_token_plain);
    let expires_at = Utc::now() + Duration::seconds(state.config.approval_ttl_seconds);

    sqlx::query(
        r#"
        INSERT INTO approvals (
          id,
          task_id,
          approval_id,
          nonce_hash,
          nonce_plain,
          resume_token_hash,
          resume_token_plain,
          state,
          expires_at,
          operation_fingerprint,
          permission_gap_json,
          approver_principal,
          created_at,
          updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9, ?10, ?11, ?12, ?12)
        "#,
    )
    .bind(new_id("aprdb"))
    .bind(task_id)
    .bind(approval_id.clone())
    .bind(nonce_hash)
    .bind(nonce_plain)
    .bind(resume_token_hash)
    .bind(resume_token_plain.clone())
    .bind(expires_at)
    .bind(operation_fingerprint)
    .bind(serde_json::to_string(&permission_check).map_err(AppError::internal)?)
    .bind(approver_principal)
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;

    let callback_id = if let Some(callback) = payload.callback.as_ref() {
        let callback_id = register_callback(&mut tx, &task_id, callback).await?;
        sqlx::query(
            r#"
            UPDATE tasks
            SET callback_id = ?1, updated_at = ?2
            WHERE id = ?3
            "#,
        )
        .bind(callback_id.clone())
        .bind(Utc::now())
        .bind(task_id.clone())
        .execute(&mut *tx)
        .await?;
        Some(callback_id)
    } else {
        None
    };

    tx.commit().await?;

    Ok(PendingApprovalCreateResult {
        approval_id,
        approval_status_url: format!("/v1/tasks/{task_id}/approval-status"),
        resume_token: resume_token_plain,
        callback_id,
    })
}

async fn register_callback(
    tx: &mut Transaction<'_, Sqlite>,
    task_id: &str,
    callback: &CallbackRegistrationInput,
) -> Result<String, AppError> {
    if callback.url.trim().is_empty() {
        return Err(AppError::BadRequest("callback.url is required".to_string()));
    }
    if callback.secret.trim().is_empty() {
        return Err(AppError::BadRequest("callback.secret is required".to_string()));
    }

    let callback_id = new_id("cbk");
    let events = if callback.events.is_empty() {
        vec![
            "approval.pending".to_string(),
            "approval.approved".to_string(),
            "approval.denied".to_string(),
            "approval.expired".to_string(),
            "apply.finished".to_string(),
            "apply.failed".to_string(),
        ]
    } else {
        callback.events.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO callbacks (
          id,
          task_id,
          event_endpoint,
          secret,
          events_json,
          status,
          created_at,
          updated_at,
          last_error
        ) VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?6, NULL)
        "#,
    )
    .bind(callback_id.clone())
    .bind(task_id)
    .bind(callback.url.clone())
    .bind(callback.secret.clone())
    .bind(serde_json::to_string(&events).map_err(AppError::internal)?)
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;

    Ok(callback_id)
}

async fn upsert_callback_for_task(
    state: &AppState,
    task_id: &str,
    callback: &CallbackRegistrationInput,
) -> Result<(), AppError> {
    let mut tx = state.db.begin().await?;

    sqlx::query(
        r#"
        UPDATE callbacks
        SET status = 'inactive', updated_at = ?1
        WHERE task_id = ?2
          AND status = 'active'
        "#,
    )
    .bind(Utc::now())
    .bind(task_id)
    .execute(&mut *tx)
    .await?;

    let callback_id = register_callback(&mut tx, task_id, callback).await?;

    sqlx::query(
        r#"
        UPDATE tasks
        SET callback_id = ?1,
            updated_at = ?2
        WHERE id = ?3
        "#,
    )
    .bind(callback_id)
    .bind(Utc::now())
    .bind(task_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(())
}

async fn fetch_agent_permissions_raw(
    tx: &mut Transaction<'_, Sqlite>,
    agent_id: &str,
) -> Result<Value, AppError> {
    let rows = sqlx::query(
        r#"
        SELECT operation_id, scope_type, scope_id, granted_level, expires_at
        FROM agent_permissions
        WHERE agent_id = ?1
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > ?2)
        ORDER BY operation_id, scope_type, scope_id
        "#,
    )
    .bind(agent_id)
    .bind(Utc::now())
    .fetch_all(&mut *tx)
    .await?;

    let mut values = Vec::new();
    for row in rows {
        values.push(json!({
            "operation_id": row.try_get::<String, _>("operation_id")?,
            "scope_type": row.try_get::<String, _>("scope_type")?,
            "scope_id": row.try_get::<String, _>("scope_id")?,
            "granted_level": row.try_get::<String, _>("granted_level")?,
            "expires_at": row.try_get::<Option<chrono::DateTime<Utc>>, _>("expires_at")?,
        }));
    }

    Ok(Value::Array(values))
}

async fn bump_or_get_agent_permission_version(
    tx: &mut Transaction<'_, Sqlite>,
    agent_id: &str,
    bump: bool,
) -> Result<i64, AppError> {
    let row = sqlx::query(
        r#"
        SELECT version
        FROM agent_permission_version
        WHERE agent_id = ?1
        LIMIT 1
        "#,
    )
    .bind(agent_id)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(row) = row {
        let current: i64 = row.try_get("version")?;
        if bump {
            let next = current + 1;
            sqlx::query(
                r#"
                UPDATE agent_permission_version
                SET version = ?1, updated_at = ?2
                WHERE agent_id = ?3
                "#,
            )
            .bind(next)
            .bind(Utc::now())
            .bind(agent_id)
            .execute(&mut *tx)
            .await?;
            Ok(next)
        } else {
            Ok(current)
        }
    } else {
        let initial = 1_i64;
        sqlx::query(
            r#"
            INSERT INTO agent_permission_version (id, agent_id, version, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?4)
            "#,
        )
        .bind(new_id("apv"))
        .bind(agent_id)
        .bind(initial)
        .bind(Utc::now())
        .execute(&mut *tx)
        .await?;
        Ok(initial)
    }
}

async fn current_agent_permission_version(state: &AppState, agent_id: &str) -> Result<i64, AppError> {
    let row = sqlx::query(
        r#"
        SELECT version
        FROM agent_permission_version
        WHERE agent_id = ?1
        LIMIT 1
        "#,
    )
    .bind(agent_id)
    .fetch_optional(&state.db)
    .await?;

    Ok(row
        .and_then(|row| row.try_get::<i64, _>("version").ok())
        .unwrap_or(1))
}

fn canonical_fingerprint(value: &Value) -> Result<String, AppError> {
    let canonical = canonicalize_json(value);
    let bytes = serde_json::to_vec(&canonical).map_err(AppError::internal)?;
    Ok(sha256_hex_bytes(&bytes))
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

fn permission_level_to_str(level: PermissionLevel) -> &'static str {
    match level {
        PermissionLevel::Read => "read",
        PermissionLevel::Write => "write",
        PermissionLevel::Admin => "admin",
    }
}

fn str_to_permission_level(value: &str) -> Result<PermissionLevel, AppError> {
    match value {
        "read" => Ok(PermissionLevel::Read),
        "write" => Ok(PermissionLevel::Write),
        "admin" => Ok(PermissionLevel::Admin),
        _ => Err(AppError::Internal(format!("invalid permission level: {value}"))),
    }
}

fn risk_tier_to_str(risk_tier: RiskTier) -> &'static str {
    match risk_tier {
        RiskTier::Safe => "safe",
        RiskTier::Elevated => "elevated",
        RiskTier::Sensitive => "sensitive",
    }
}
