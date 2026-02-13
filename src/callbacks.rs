use std::{net::IpAddr, time::Duration};

use chrono::{Duration as ChronoDuration, Utc};
use hmac::{Hmac, Mac};
use reqwest::Url;
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::Row;
use tokio::net::lookup_host;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::{
    db::new_id,
    error::AppError,
    models::{CallbackEnvelope, CallbackEvent},
    state::AppState,
};

type HmacSha256 = Hmac<Sha256>;

pub async fn enqueue_callback_event(
    state: &AppState,
    task_id: &str,
    event_type: &str,
    approval_id: Option<String>,
    idempotency_key: Option<String>,
    payload: Value,
) -> Result<(), AppError> {
    let callback_row = sqlx::query(
        r#"
        SELECT id, event_endpoint, events_json, secret, status
        FROM callbacks
        WHERE task_id = ?1
          AND status = 'active'
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(task_id)
    .fetch_optional(&state.db)
    .await?;

    let Some(callback_row) = callback_row else {
        return Ok(());
    };

    let events_json: String = callback_row.try_get("events_json")?;
    let allowed_events: Vec<String> = serde_json::from_str(&events_json).unwrap_or_default();
    if !allowed_events.is_empty() && !allowed_events.iter().any(|e| e == event_type) {
        return Ok(());
    }

    let callback_id: String = callback_row.try_get("id")?;
    let event = CallbackEvent {
        event_id: new_id("evt"),
        event_type: event_type.to_string(),
        task_id: task_id.to_string(),
        approval_id,
        idempotency_key,
        timestamp: Utc::now(),
        payload,
    };

    let envelope = CallbackEnvelope { event };
    let payload_json = serde_json::to_value(envelope).map_err(AppError::internal)?;

    sqlx::query(
        r#"
        INSERT INTO callback_deliveries (
          id,
          callback_id,
          event_id,
          payload_json,
          attempt_count,
          next_retry_at,
          last_status,
          last_error,
          created_at,
          updated_at
        ) VALUES (?1, ?2, ?3, ?4, 0, ?5, NULL, NULL, ?5, ?5)
        "#,
    )
    .bind(new_id("cdel"))
    .bind(callback_id)
    .bind(
        payload_json
            .get("event")
            .and_then(|e| e.get("event_id"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
    )
    .bind(payload_json.to_string())
    .bind(Utc::now())
    .execute(&state.db)
    .await?;

    Ok(())
}

pub fn start_callback_worker(state: AppState) {
    tokio::spawn(async move {
        loop {
            if let Err(err) = process_due_deliveries(&state).await {
                error!(error = %err, "callback worker iteration failed");
            }

            if let Err(err) = process_expired_approvals(&state).await {
                error!(error = %err, "approval expiration iteration failed");
            }

            sleep(Duration::from_secs(
                state.config.callback_worker_interval_secs,
            ))
            .await;
        }
    });
}

async fn process_due_deliveries(state: &AppState) -> Result<(), AppError> {
    let rows = sqlx::query(
        r#"
        SELECT
          d.id,
          d.callback_id,
          d.event_id,
          d.payload_json,
          d.attempt_count,
          c.event_endpoint,
          c.secret
        FROM callback_deliveries d
        JOIN callbacks c ON c.id = d.callback_id
        WHERE d.delivered_at IS NULL
          AND d.next_retry_at <= ?1
          AND c.status = 'active'
        ORDER BY d.next_retry_at ASC
        LIMIT ?2
        "#,
    )
    .bind(Utc::now())
    .bind(state.config.callback_batch_size as i64)
    .fetch_all(&state.db)
    .await?;

    for row in rows {
        let delivery_id: String = row.try_get("id")?;
        let event_id: String = row.try_get("event_id")?;
        let payload_json: String = row.try_get("payload_json")?;
        let attempt_count: i64 = row.try_get("attempt_count")?;
        let endpoint: String = row.try_get("event_endpoint")?;
        let secret: String = row.try_get("secret")?;

        if let Err(err) = validate_callback_delivery_endpoint(state, &endpoint).await {
            handle_delivery_retry(state, &delivery_id, attempt_count, err.to_string()).await?;
            continue;
        }

        let signature = sign_callback_payload(&secret, &payload_json)?;
        let response = state
            .callback_http_client
            .post(&endpoint)
            .header("content-type", "application/json")
            .header("x-llm-proxy-event-id", event_id.clone())
            .header("x-llm-proxy-signature", signature)
            .body(payload_json.clone())
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                sqlx::query(
                    r#"
                    UPDATE callback_deliveries
                    SET delivered_at = ?1,
                        last_status = ?2,
                        last_error = NULL,
                        updated_at = ?1
                    WHERE id = ?3
                    "#,
                )
                .bind(Utc::now())
                .bind(resp.status().as_u16() as i64)
                .bind(delivery_id)
                .execute(&state.db)
                .await?;
            }
            Ok(resp) => {
                handle_delivery_retry(
                    state,
                    &delivery_id,
                    attempt_count,
                    format!("http status {}", resp.status()),
                )
                .await?;
            }
            Err(err) => {
                handle_delivery_retry(state, &delivery_id, attempt_count, err.to_string()).await?;
            }
        }
    }

    Ok(())
}

async fn handle_delivery_retry(
    state: &AppState,
    delivery_id: &str,
    attempt_count: i64,
    error_message: String,
) -> Result<(), AppError> {
    let next_attempt = attempt_count + 1;

    if next_attempt >= state.config.callback_max_retries as i64 {
        warn!(delivery_id, error = %error_message, "callback delivery exhausted retries");
        sqlx::query(
            r#"
            UPDATE callback_deliveries
            SET attempt_count = ?1,
                last_error = ?2,
                updated_at = ?3,
                next_retry_at = NULL
            WHERE id = ?4
            "#,
        )
        .bind(next_attempt)
        .bind(error_message)
        .bind(Utc::now())
        .bind(delivery_id)
        .execute(&state.db)
        .await?;
        return Ok(());
    }

    let backoff_seconds = 2_i64.pow(next_attempt as u32);
    let next_retry_at = Utc::now() + ChronoDuration::seconds(backoff_seconds);

    sqlx::query(
        r#"
        UPDATE callback_deliveries
        SET attempt_count = ?1,
            next_retry_at = ?2,
            last_error = ?3,
            updated_at = ?4
        WHERE id = ?5
        "#,
    )
    .bind(next_attempt)
    .bind(next_retry_at)
    .bind(error_message)
    .bind(Utc::now())
    .bind(delivery_id)
    .execute(&state.db)
    .await?;

    Ok(())
}

fn sign_callback_payload(secret: &str, payload: &str) -> Result<String, AppError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| AppError::internal(format!("hmac init failed: {e}")))?;
    mac.update(payload.as_bytes());
    let signature = mac.finalize().into_bytes();
    Ok(format!("v1={}", hex::encode(signature)))
}

async fn validate_callback_delivery_endpoint(
    state: &AppState,
    endpoint: &str,
) -> Result<(), AppError> {
    let url = Url::parse(endpoint)
        .map_err(|_| AppError::BadRequest("callback endpoint is not a valid URL".to_string()))?;
    if url.scheme() != "https" {
        return Err(AppError::BadRequest(
            "callback endpoint must use https".to_string(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AppError::BadRequest(
            "callback endpoint must not include credentials".to_string(),
        ));
    }
    if url.fragment().is_some() {
        return Err(AppError::BadRequest(
            "callback endpoint must not include fragments".to_string(),
        ));
    }

    let host = url.host_str().ok_or_else(|| {
        AppError::BadRequest("callback endpoint must include a hostname".to_string())
    })?;
    if !state.config.is_callback_host_allowed(host) {
        return Err(AppError::BadRequest(
            "callback endpoint host is not allowlisted".to_string(),
        ));
    }

    let port = url.port_or_known_default().ok_or_else(|| {
        AppError::BadRequest("callback endpoint must include a valid port".to_string())
    })?;
    let addrs = lookup_host((host, port)).await.map_err(|_| {
        AppError::BadRequest("callback endpoint host resolution failed".to_string())
    })?;

    for addr in addrs {
        if is_restricted_ip(addr.ip()) {
            return Err(AppError::BadRequest(
                "callback endpoint resolves to restricted network ranges".to_string(),
            ));
        }
    }

    Ok(())
}

fn is_restricted_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)
        }
    }
}

async fn process_expired_approvals(state: &AppState) -> Result<(), AppError> {
    let expired = sqlx::query(
        r#"
        SELECT id, task_id, approval_id
        FROM approvals
        WHERE state = 'pending'
          AND expires_at < ?1
        "#,
    )
    .bind(Utc::now())
    .fetch_all(&state.db)
    .await?;
    let expired_count = expired.len();

    for row in expired {
        let id: String = row.try_get("id")?;
        let task_id: String = row.try_get("task_id")?;
        let approval_id: String = row.try_get("approval_id")?;

        sqlx::query(
            r#"
            UPDATE approvals
            SET state = 'expired', updated_at = ?1
            WHERE id = ?2
            "#,
        )
        .bind(Utc::now())
        .bind(id)
        .execute(&state.db)
        .await?;

        sqlx::query(
            r#"
            UPDATE tasks
            SET status = 'expired', apply_state = 'waiting_approval', updated_at = ?1
            WHERE id = ?2
            "#,
        )
        .bind(Utc::now())
        .bind(task_id.clone())
        .execute(&state.db)
        .await?;

        enqueue_callback_event(
            state,
            &task_id,
            "approval.expired",
            Some(approval_id),
            None,
            json!({"reason": "approval expired"}),
        )
        .await?;
    }

    if expired_count > 0 {
        info!(count = expired_count, "processed expired approvals");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{enqueue_callback_event, handle_delivery_retry, process_expired_approvals};
    use crate::{
        cf::CloudflareExecutor, config::Config, db::connect_and_bootstrap, state::AppState,
    };
    use chrono::{Duration, Utc};
    use reqwest::Client;
    use serde_json::json;
    use sqlx::Row;
    use tempfile::TempDir;

    async fn build_state() -> (AppState, TempDir) {
        let temp = TempDir::new().expect("tempdir should be created");
        let db_path = temp.path().join("callbacks-test.db");
        let config = Config {
            bind_addr: "127.0.0.1:0".to_string(),
            database_url: format!("sqlite://{}", db_path.display()),
            jwt_secret: "test-secret".to_string(),
            jwt_issuer: "issuer".to_string(),
            jwt_audience: "aud".to_string(),
            bootstrap_jwt_secret: "bootstrap-secret".to_string(),
            bootstrap_jwt_issuer: "bootstrap-issuer".to_string(),
            bootstrap_jwt_audience: "bootstrap-aud".to_string(),
            mtls_binding_shared_secret: "mtls-secret".to_string(),
            approval_link_secret: "approval-secret".to_string(),
            resume_token_secret: "resume-secret".to_string(),
            base_url: "http://localhost".to_string(),
            callback_allowed_hosts: ["localhost".to_string()].into_iter().collect(),
            callback_max_retries: 2,
            callback_batch_size: 50,
            callback_worker_interval_secs: 1,
            approval_ttl_seconds: 600,
            approval_nonce_ttl_seconds: 90,
            webauthn_rp_id: "localhost".to_string(),
            webauthn_origin: "http://localhost:8080".to_string(),
            cloudflare_api_token: None,
            cloudflare_api_base: "https://api.cloudflare.com/client/v4".to_string(),
            allow_insecure_defaults: true,
        };

        let db = connect_and_bootstrap(&config)
            .await
            .expect("db bootstrap should succeed");
        let client = Client::new();
        let cf_executor =
            CloudflareExecutor::new(None, config.cloudflare_api_base.clone(), client.clone());

        (
            AppState {
                config,
                db,
                http_client: client,
                callback_http_client: Client::new(),
                cf_executor,
            },
            temp,
        )
    }

    async fn seed_task_and_callback(state: &AppState, task_id: &str, events: &[&str]) {
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO tasks (id, task_name, status, apply_state, callback_id, state_json, created_at, updated_at) VALUES (?1, 'task', 'open', 'idle', 'cbk_1', '{}', ?2, ?2)",
        )
        .bind(task_id)
        .bind(now)
        .execute(&state.db)
        .await
        .expect("task insert should succeed");

        sqlx::query(
            "INSERT INTO callbacks (id, task_id, event_endpoint, secret, events_json, status, created_at, updated_at, last_error) VALUES ('cbk_1', ?1, 'https://localhost:9/callback', 'secret', ?2, 'active', ?3, ?3, NULL)",
        )
        .bind(task_id)
        .bind(serde_json::to_string(&events).expect("events to json"))
        .bind(now)
        .execute(&state.db)
        .await
        .expect("callback insert should succeed");
    }

    #[tokio::test]
    async fn enqueue_callback_event_filters_by_event_type() {
        let (state, _temp) = build_state().await;
        seed_task_and_callback(&state, "task_cb_filter", &["approval.pending"]).await;

        enqueue_callback_event(
            &state,
            "task_cb_filter",
            "apply.finished",
            None,
            None,
            json!({"status":"done"}),
        )
        .await
        .expect("enqueue should succeed");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM callback_deliveries")
            .fetch_one(&state.db)
            .await
            .expect("count query should succeed");
        assert_eq!(count, 0);

        enqueue_callback_event(
            &state,
            "task_cb_filter",
            "approval.pending",
            Some("appr-1".to_string()),
            Some("idem-1".to_string()),
            json!({"status":"pending"}),
        )
        .await
        .expect("enqueue should succeed");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM callback_deliveries")
            .fetch_one(&state.db)
            .await
            .expect("count query should succeed");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn handle_delivery_retry_marks_terminal_after_max_retries() {
        let (state, _temp) = build_state().await;
        seed_task_and_callback(&state, "task_cb_retry", &[]).await;
        let now = Utc::now();

        sqlx::query(
            "INSERT INTO callback_deliveries (id, callback_id, event_id, payload_json, attempt_count, next_retry_at, last_status, last_error, delivered_at, created_at, updated_at) VALUES ('cdel_1', 'cbk_1', 'evt_1', '{}', 1, ?1, NULL, NULL, NULL, ?1, ?1)",
        )
        .bind(now)
        .execute(&state.db)
        .await
        .expect("delivery insert should succeed");

        handle_delivery_retry(&state, "cdel_1", 1, "boom".to_string())
            .await
            .expect("retry handler should succeed");

        let row = sqlx::query(
            "SELECT attempt_count, next_retry_at, last_error FROM callback_deliveries WHERE id = 'cdel_1'",
        )
        .fetch_one(&state.db)
        .await
        .expect("delivery should exist");

        let attempt_count: i64 = row.try_get("attempt_count").expect("attempt_count");
        let next_retry_at: Option<chrono::DateTime<Utc>> =
            row.try_get("next_retry_at").expect("next_retry_at");
        let last_error: String = row.try_get("last_error").expect("last_error");

        assert_eq!(attempt_count, 2);
        assert!(next_retry_at.is_none());
        assert_eq!(last_error, "boom");
    }

    #[tokio::test]
    async fn process_expired_approvals_transitions_state() {
        let (state, _temp) = build_state().await;
        let now = Utc::now();
        let expired = now - Duration::seconds(5);

        sqlx::query(
            "INSERT INTO tasks (id, task_name, status, apply_state, callback_id, state_json, created_at, updated_at) VALUES ('task_exp_1', 'task', 'open', 'waiting_approval', NULL, '{}', ?1, ?1)",
        )
        .bind(now)
        .execute(&state.db)
        .await
        .expect("task insert should succeed");

        sqlx::query(
            "INSERT INTO approvals (id, task_id, approval_id, state, expires_at, operation_fingerprint, permission_gap_json, approver_principal, approved_by, approved_at, denied_reason, consumed_at, created_at, updated_at) VALUES ('aprdb_1', 'task_exp_1', 'appr_exp_1', 'pending', ?1, 'fp', '{}', 'default', NULL, NULL, NULL, NULL, ?2, ?2)",
        )
        .bind(expired)
        .bind(now)
        .execute(&state.db)
        .await
        .expect("approval insert should succeed");

        process_expired_approvals(&state)
            .await
            .expect("expiration processing should succeed");

        let approval_state: String =
            sqlx::query_scalar("SELECT state FROM approvals WHERE approval_id = 'appr_exp_1'")
                .fetch_one(&state.db)
                .await
                .expect("approval query should succeed");
        let task_status: String =
            sqlx::query_scalar("SELECT status FROM tasks WHERE id = 'task_exp_1'")
                .fetch_one(&state.db)
                .await
                .expect("task query should succeed");

        assert_eq!(approval_state, "expired");
        assert_eq!(task_status, "expired");
    }
}
