mod common;

use axum::{
    body::Body,
    http::{HeaderValue, Request, StatusCode},
};
use common::{TestApp, build_test_app, json_auth_request, json_request};
use llm_permission_proxy::auth::{issue_bootstrap_token, make_bootstrap_claims};
use serde_json::{Value, json};

fn bootstrap_token(
    app: &TestApp,
    sub: &str,
    mtls_subject: &str,
    can_issue_tasks: bool,
    can_manage_permissions: bool,
    can_manage_approvers: bool,
) -> String {
    let claims = make_bootstrap_claims(
        &app.config.bootstrap_jwt_issuer,
        &app.config.bootstrap_jwt_audience,
        sub,
        "bootstrap-jti".to_string(),
        3600,
        mtls_subject.to_string(),
        can_issue_tasks,
        can_manage_permissions,
        can_manage_approvers,
    );
    issue_bootstrap_token(&claims, &app.config.bootstrap_jwt_secret)
        .expect("bootstrap token should be signed")
}

async fn create_task(
    app: &TestApp,
    bootstrap_token: &str,
    mtls_subject: &str,
    task_name: &str,
    operations: Value,
    callback: Option<Value>,
) -> (StatusCode, Value) {
    let mut body = json!({
        "task_name": task_name,
        "operations": operations
    });
    if let Some(callback) = callback {
        body["callback"] = callback;
    }
    let req = json_auth_request(
        "POST",
        "/v1/tasks",
        bootstrap_token,
        mtls_subject,
        &app.config.mtls_binding_shared_secret,
        body,
    );
    app.send(req).await
}

async fn apply(
    app: &TestApp,
    task_id: &str,
    capability_token: &str,
    mtls_subject: &str,
    idempotency_key: &str,
    operations: Value,
) -> (StatusCode, Value) {
    let mut req = json_auth_request(
        "POST",
        &format!("/v1/tasks/{task_id}/apply"),
        capability_token,
        mtls_subject,
        &app.config.mtls_binding_shared_secret,
        json!({"operations": operations}),
    );
    req.headers_mut().insert(
        "idempotency-key",
        HeaderValue::from_str(idempotency_key).expect("idempotency key should parse"),
    );
    app.send(req).await
}

async fn continue_apply(
    app: &TestApp,
    task_id: &str,
    capability_token: &str,
    mtls_subject: &str,
    idempotency_key: &str,
    resume_token: &str,
) -> (StatusCode, Value) {
    let mut req = json_auth_request(
        "POST",
        &format!("/v1/tasks/{task_id}/apply/continue"),
        capability_token,
        mtls_subject,
        &app.config.mtls_binding_shared_secret,
        json!({"resume_token": resume_token}),
    );
    req.headers_mut().insert(
        "idempotency-key",
        HeaderValue::from_str(idempotency_key).expect("idempotency key should parse"),
    );
    app.send(req).await
}

#[tokio::test]
async fn health_and_ready_endpoints_return_ok() {
    let app = build_test_app().await;

    let req = Request::builder()
        .method("GET")
        .uri("/v1/healthz")
        .body(Body::empty())
        .expect("request should build");
    let (status, body) = app.send(req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], json!(true));

    let req = Request::builder()
        .method("GET")
        .uri("/v1/readyz")
        .body(Body::empty())
        .expect("request should build");
    let (status, body) = app.send(req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ready"], json!(true));
}

#[tokio::test]
async fn create_task_requires_bootstrap_auth() {
    let app = build_test_app().await;
    let req = json_request(
        "POST",
        "/v1/tasks",
        json!({
            "task_name": "t1",
            "operations": [{
                "operation_id":"dns.record.read",
                "scope_type":"zone",
                "scope_id":"zone1"
            }]
        }),
    );
    let (status, body) = app.send(req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], json!("unauthorized"));
}

#[tokio::test]
async fn create_task_rejects_permissions_admin_operation() {
    let app = build_test_app().await;
    let token = bootstrap_token(&app, "agent:issuer", "mtls-issuer", true, true, true);
    let (status, body) = create_task(
        &app,
        &token,
        "mtls-issuer",
        "bad-task",
        json!([{
            "operation_id":"permissions.admin",
            "scope_type":"account",
            "scope_id":"acc1"
        }]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body["message"]
            .as_str()
            .expect("message should exist")
            .contains("cannot be included")
    );
}

#[tokio::test]
async fn task_token_cannot_access_admin_endpoints() {
    let app = build_test_app().await;
    let bootstrap = bootstrap_token(&app, "agent:issuer", "mtls-issuer", true, true, true);
    let (status, created) = create_task(
        &app,
        &bootstrap,
        "mtls-issuer",
        "task-token",
        json!([{
            "operation_id":"dns.record.read",
            "scope_type":"zone",
            "scope_id":"zone1"
        }]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let task_token = created["capability_token"]
        .as_str()
        .expect("capability token should be present")
        .to_string();

    let req = json_auth_request(
        "PATCH",
        "/v1/agents/agent-x/permissions",
        &task_token,
        "mtls-issuer",
        &app.config.mtls_binding_shared_secret,
        json!({
            "permissions": [{
                "operation_id":"dns.record.read",
                "scope_type":"zone",
                "scope_id":"zone1",
                "granted_level":"read"
            }]
        }),
    );
    let (status, body) = app.send(req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], json!("unauthorized"));
}

#[tokio::test]
async fn bootstrap_token_can_manage_permissions() {
    let app = build_test_app().await;
    let bootstrap = bootstrap_token(&app, "agent:issuer", "mtls-issuer", true, true, false);

    let req = json_auth_request(
        "PATCH",
        "/v1/agents/agent-a/permissions",
        &bootstrap,
        "mtls-issuer",
        &app.config.mtls_binding_shared_secret,
        json!({
            "permissions": [{
                "operation_id":"dns.record.read",
                "scope_type":"zone",
                "scope_id":"zone1",
                "granted_level":"read"
            }]
        }),
    );
    let (status, body) = app.send(req).await;
    assert_eq!(status, StatusCode::OK, "unexpected body: {body}");
    assert_eq!(body["agent_id"], json!("agent-a"));
}

#[tokio::test]
async fn create_task_rejects_non_allowlisted_callback_host() {
    let app = build_test_app().await;
    let bootstrap = bootstrap_token(&app, "agent:issuer", "mtls-issuer", true, true, true);
    let (status, body) = create_task(
        &app,
        &bootstrap,
        "mtls-issuer",
        "callback-bad-host",
        json!([{
            "operation_id":"dns.record.read",
            "scope_type":"zone",
            "scope_id":"zone1"
        }]),
        Some(json!({
            "url":"https://evil.example/callback",
            "secret":"shh",
            "events":["apply.finished"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"]
            .as_str()
            .expect("message should exist")
            .contains("allowlisted")
    );
}

#[tokio::test]
async fn task_routes_require_signed_mtls_headers() {
    let app = build_test_app().await;
    let bootstrap = bootstrap_token(&app, "agent:issuer", "mtls-issuer", true, true, true);
    let (status, created) = create_task(
        &app,
        &bootstrap,
        "mtls-issuer",
        "task-mtls",
        json!([{
            "operation_id":"dns.record.read",
            "scope_type":"zone",
            "scope_id":"zone1"
        }]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let task_id = created["task_id"]
        .as_str()
        .expect("task_id should exist")
        .to_string();
    let task_token = created["capability_token"]
        .as_str()
        .expect("capability token should exist")
        .to_string();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/tasks/{task_id}"))
        .header("authorization", format!("Bearer {task_token}"))
        .header("x-client-subject", "mtls-issuer")
        .body(Body::empty())
        .expect("request should build");
    let (status, body) = app.send(req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], json!("unauthorized"));
}

#[tokio::test]
async fn continue_apply_rejects_invalid_resume_token() {
    let app = build_test_app().await;
    let bootstrap = bootstrap_token(&app, "agent:issuer", "mtls-issuer", true, true, true);
    let (status, created) = create_task(
        &app,
        &bootstrap,
        "mtls-issuer",
        "resume-invalid",
        json!([{
            "operation_id":"workers.deploy.write",
            "scope_type":"account",
            "scope_id":"acc1"
        }]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let task_id = created["task_id"]
        .as_str()
        .expect("task_id should exist")
        .to_string();
    let task_token = created["capability_token"]
        .as_str()
        .expect("capability token should exist")
        .to_string();

    let ops = json!([{
        "operation_id":"workers.deploy.write",
        "scope_type":"account",
        "scope_id":"acc1",
        "params":{"script_name":"edge-script","script":"addEventListener('fetch',()=>{})"}
    }]);

    let (status, body) = apply(
        &app,
        &task_id,
        &task_token,
        "mtls-issuer",
        "idem-resume-invalid",
        ops,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "unexpected body: {body}");
    assert_eq!(body["status"], json!("requires_approval"));

    let (status, body) = continue_apply(
        &app,
        &task_id,
        &task_token,
        "mtls-issuer",
        "idem-resume-invalid",
        "not-a-real-token",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], json!("unauthorized"));
}
