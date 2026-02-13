use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use llm_permission_proxy::{
    cf::CloudflareExecutor, config::Config, db::connect_and_bootstrap, handlers::router,
    state::AppState,
};
use reqwest::{Client, redirect::Policy};
use serde_json::Value;
use sha2::Sha256;
use tempfile::TempDir;
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

pub struct TestApp {
    pub app: Router,
    pub config: Config,
    _temp_dir: TempDir,
}

impl TestApp {
    pub async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("request should execute");
        let status = response.status();
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body should be readable");
        let parsed = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
        (status, parsed)
    }
}

pub async fn build_test_app() -> TestApp {
    let temp_dir = TempDir::new().expect("temp directory should be created");
    let db_path = temp_dir.path().join("test-proxy.db");
    let db_url = format!("sqlite://{}", db_path.display());
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be monotonic")
        .as_nanos();

    let config = Config {
        bind_addr: "127.0.0.1:0".to_string(),
        database_url: db_url,
        jwt_secret: format!("secret-{unique}"),
        jwt_issuer: "llm-permission-proxy".to_string(),
        jwt_audience: "llm-proxy-api".to_string(),
        bootstrap_jwt_secret: format!("bootstrap-secret-{unique}"),
        bootstrap_jwt_issuer: "llm-permission-proxy-bootstrap".to_string(),
        bootstrap_jwt_audience: "llm-proxy-bootstrap".to_string(),
        mtls_binding_shared_secret: format!("mtls-secret-{unique}"),
        approval_link_secret: format!("approval-secret-{unique}"),
        resume_token_secret: format!("resume-secret-{unique}"),
        base_url: "http://localhost:8080".to_string(),
        callback_allowed_hosts: ["localhost".to_string()].into_iter().collect(),
        callback_max_retries: 2,
        callback_batch_size: 50,
        callback_worker_interval_secs: 1,
        approval_ttl_seconds: 600,
        approval_nonce_ttl_seconds: 120,
        webauthn_rp_id: "localhost".to_string(),
        webauthn_origin: "http://localhost:8080".to_string(),
        cloudflare_api_token: None,
        cloudflare_api_base: "https://api.cloudflare.com/client/v4".to_string(),
        allow_insecure_defaults: true,
    };

    let db = connect_and_bootstrap(&config)
        .await
        .expect("db bootstrap should succeed");
    let http_client = Client::new();
    let callback_http_client = Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("callback client should build");
    let cf_executor = CloudflareExecutor::new(
        None,
        config.cloudflare_api_base.clone(),
        http_client.clone(),
    );

    let state = AppState {
        config: config.clone(),
        db,
        http_client,
        callback_http_client,
        cf_executor,
    };
    let app = router(state);

    TestApp {
        app,
        config,
        _temp_dir: temp_dir,
    }
}

pub fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request should build")
}

pub fn json_auth_request(
    method: &str,
    uri: &str,
    token: &str,
    mtls_subject: &str,
    mtls_binding_secret: &str,
    body: Value,
) -> Request<Body> {
    let ts = Utc::now().timestamp();
    let signature = sign_mtls_headers(mtls_subject, ts, mtls_binding_secret);
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("x-client-subject", mtls_subject)
        .header("x-client-subject-ts", ts.to_string())
        .header("x-client-subject-sig", signature)
        .body(Body::from(body.to_string()))
        .expect("request should build")
}

pub fn sign_mtls_headers(subject: &str, ts: i64, secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key should be acceptable");
    mac.update(format!("{subject}\n{ts}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
