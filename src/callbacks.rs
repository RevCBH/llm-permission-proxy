use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::Row;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::{db::new_id, error::AppError, models::{CallbackEnvelope, CallbackEvent}, state::AppState};

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
    .bind(payload_json
        .get("event")
        .and_then(|e| e.get("event_id"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string())
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

            sleep(Duration::from_secs(state.config.callback_worker_interval_secs)).await;
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

        let signature = sign_callback_payload(&secret, &payload_json)?;
        let response = state
            .http_client
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
