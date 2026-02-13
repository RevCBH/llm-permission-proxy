use std::{str::FromStr, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use uuid::Uuid;

use crate::{config::Config, error::AppError};

pub async fn connect_and_bootstrap(config: &Config) -> Result<SqlitePool, AppError> {
    let options = SqliteConnectOptions::from_str(&config.database_url)
        .map_err(AppError::internal)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    bootstrap_schema(&pool).await?;

    Ok(pool)
}

const SCHEMA_BOOTSTRAP_SQL: &[&str] = &[
    "PRAGMA foreign_keys = ON;",
    "CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      task_name TEXT NOT NULL,
      status TEXT NOT NULL,
      apply_state TEXT NOT NULL,
      callback_id TEXT,
      state_json TEXT,
      last_error TEXT,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL
    );",
    "CREATE TABLE IF NOT EXISTS task_operations (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      operation_id TEXT NOT NULL,
      scope_type TEXT NOT NULL,
      scope_id TEXT NOT NULL,
      required_level TEXT NOT NULL,
      risk_tier TEXT NOT NULL,
      created_at DATETIME NOT NULL,
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );",
    "CREATE TABLE IF NOT EXISTS capability_tokens (
      jti TEXT PRIMARY KEY,
      task_id TEXT,
      agent_id TEXT NOT NULL,
      mtls_subject TEXT NOT NULL,
      aud TEXT NOT NULL,
      iss TEXT NOT NULL,
      allowed_ops_json TEXT NOT NULL,
      resource_scopes_json TEXT NOT NULL,
      claims_hash TEXT NOT NULL,
      expires_at DATETIME NOT NULL,
      revoked_at DATETIME,
      rev INTEGER NOT NULL,
      created_at DATETIME NOT NULL,
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE SET NULL
    );",
    "CREATE TABLE IF NOT EXISTS agent_permissions (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      operation_id TEXT NOT NULL,
      scope_type TEXT NOT NULL,
      scope_id TEXT NOT NULL,
      granted_level TEXT NOT NULL,
      source TEXT NOT NULL,
      not_before DATETIME NOT NULL,
      expires_at DATETIME,
      revoked_at DATETIME,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL
    );",
    "CREATE TABLE IF NOT EXISTS agent_permission_version (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL UNIQUE,
      version INTEGER NOT NULL,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL
    );",
    "CREATE TABLE IF NOT EXISTS task_permission_snapshot (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      granted_permissions_json TEXT NOT NULL,
      snapshot_version INTEGER NOT NULL,
      snapshot_at DATETIME NOT NULL,
      snapshot_ttl_at DATETIME,
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );",
    "CREATE TABLE IF NOT EXISTS permission_evaluations (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      apply_request_id TEXT NOT NULL,
      requested_permissions_json TEXT NOT NULL,
      granted_permissions_json TEXT NOT NULL,
      missing_permissions_json TEXT NOT NULL,
      requires_approval INTEGER NOT NULL,
      created_at DATETIME NOT NULL,
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );",
    "CREATE TABLE IF NOT EXISTS idempotency_records (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      idempotency_key_hash TEXT NOT NULL,
      operation_fingerprint TEXT NOT NULL,
      status TEXT NOT NULL,
      request_json TEXT NOT NULL,
      response_json TEXT,
      approval_id TEXT,
      http_status INTEGER,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL,
      expires_at DATETIME,
      UNIQUE(task_id, idempotency_key_hash),
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );",
    "CREATE TABLE IF NOT EXISTS approvals (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      approval_id TEXT NOT NULL UNIQUE,
      state TEXT NOT NULL,
      expires_at DATETIME NOT NULL,
      operation_fingerprint TEXT NOT NULL,
      permission_gap_json TEXT NOT NULL,
      approver_principal TEXT NOT NULL,
      approved_by TEXT,
      approved_at DATETIME,
      denied_reason TEXT,
      consumed_at DATETIME,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL,
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );",
    "CREATE TABLE IF NOT EXISTS webauthn_challenges (
      id TEXT PRIMARY KEY,
      approval_id TEXT NOT NULL,
      challenge TEXT NOT NULL,
      challenge_hash TEXT NOT NULL,
      created_at DATETIME NOT NULL,
      expires_at DATETIME NOT NULL,
      used_at DATETIME,
      FOREIGN KEY(approval_id) REFERENCES approvals(approval_id) ON DELETE CASCADE
    );",
    "CREATE TABLE IF NOT EXISTS approver_credentials (
      id TEXT PRIMARY KEY,
      approver_principal TEXT NOT NULL,
      credential_id TEXT NOT NULL,
      status TEXT NOT NULL,
      algorithm TEXT NOT NULL DEFAULT 'ES256',
      public_key_format TEXT NOT NULL DEFAULT 'cose',
      public_key_b64 TEXT NOT NULL,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL,
      UNIQUE(approver_principal, credential_id)
    );",
    "CREATE TABLE IF NOT EXISTS callbacks (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      event_endpoint TEXT NOT NULL,
      secret TEXT NOT NULL,
      events_json TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL,
      last_error TEXT,
      FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );",
    "CREATE TABLE IF NOT EXISTS callback_deliveries (
      id TEXT PRIMARY KEY,
      callback_id TEXT NOT NULL,
      event_id TEXT NOT NULL UNIQUE,
      payload_json TEXT NOT NULL,
      attempt_count INTEGER NOT NULL,
      next_retry_at DATETIME,
      last_status INTEGER,
      last_error TEXT,
      delivered_at DATETIME,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL,
      FOREIGN KEY(callback_id) REFERENCES callbacks(id) ON DELETE CASCADE
    );",
    "CREATE TABLE IF NOT EXISTS audit_events (
      id TEXT PRIMARY KEY,
      ts DATETIME NOT NULL,
      task_id TEXT,
      approval_id TEXT,
      actor_agent TEXT,
      actor_mtls_subject TEXT,
      action TEXT NOT NULL,
      request_id TEXT,
      cloudflare_request_id TEXT,
      input_json TEXT,
      decision TEXT,
      outcome_json TEXT,
      signature TEXT,
      correlation_id TEXT
    );",
    "CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);",
    "CREATE INDEX IF NOT EXISTS idx_capability_task ON capability_tokens(task_id);",
    "CREATE INDEX IF NOT EXISTS idx_capability_expires ON capability_tokens(expires_at);",
    "CREATE INDEX IF NOT EXISTS idx_agent_permissions_lookup
      ON agent_permissions(agent_id, operation_id, scope_type, scope_id, revoked_at, expires_at);",
    "CREATE INDEX IF NOT EXISTS idx_task_permission_snapshot_task
      ON task_permission_snapshot(task_id);",
    "CREATE INDEX IF NOT EXISTS idx_permission_evals_task
      ON permission_evaluations(task_id, apply_request_id);",
    "CREATE INDEX IF NOT EXISTS idx_approver_credentials_principal_status
      ON approver_credentials(approver_principal, status);",
    "CREATE INDEX IF NOT EXISTS idx_idempotency_lookup
      ON idempotency_records(task_id, idempotency_key_hash);",
    "CREATE INDEX IF NOT EXISTS idx_approvals_task_state
      ON approvals(task_id, state, created_at);",
    "CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_approval
      ON webauthn_challenges(approval_id, used_at, created_at);",
    "CREATE INDEX IF NOT EXISTS idx_callback_deliveries_due
      ON callback_deliveries(next_retry_at, delivered_at);",
    "CREATE INDEX IF NOT EXISTS idx_callback_deliveries_callback
      ON callback_deliveries(callback_id);",
];

async fn bootstrap_schema(pool: &SqlitePool) -> Result<(), AppError> {
    for statement in SCHEMA_BOOTSTRAP_SQL {
        sqlx::query(statement).execute(pool).await?;
    }
    Ok(())
}

pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::now_v7())
}

pub fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn sha256_hex_bytes(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hex::encode(hasher.finalize())
}

pub fn random_token(byte_len: usize) -> String {
    let mut bytes = vec![0_u8; byte_len];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn utc_now() -> chrono::DateTime<Utc> {
    Utc::now()
}

#[cfg(test)]
mod tests {
    use super::{connect_and_bootstrap, new_id, random_token, sha256_hex, sha256_hex_bytes};
    use crate::config::Config;
    use sqlx::Row;
    use tempfile::TempDir;

    fn test_config(database_url: String) -> Config {
        Config {
            bind_addr: "127.0.0.1:0".to_string(),
            database_url,
            jwt_secret: "secret".to_string(),
            jwt_issuer: "issuer".to_string(),
            jwt_audience: "aud".to_string(),
            bootstrap_jwt_secret: "bootstrap-secret".to_string(),
            bootstrap_jwt_issuer: "bootstrap-issuer".to_string(),
            bootstrap_jwt_audience: "bootstrap-audience".to_string(),
            mtls_binding_shared_secret: "mtls-secret".to_string(),
            approval_link_secret: "approval-secret".to_string(),
            resume_token_secret: "resume-secret".to_string(),
            base_url: "http://localhost".to_string(),
            callback_allowed_hosts: ["localhost".to_string()].into_iter().collect(),
            callback_max_retries: 3,
            callback_batch_size: 25,
            callback_worker_interval_secs: 1,
            approval_ttl_seconds: 300,
            approval_nonce_ttl_seconds: 60,
            webauthn_rp_id: "localhost".to_string(),
            webauthn_origin: "http://localhost".to_string(),
            cloudflare_api_token: None,
            cloudflare_api_base: "https://api.cloudflare.com/client/v4".to_string(),
            allow_insecure_defaults: true,
        }
    }

    #[tokio::test]
    async fn connect_and_bootstrap_creates_required_columns() {
        let temp = TempDir::new().expect("tempdir should be created");
        let db_path = temp.path().join("bootstrap.db");
        let cfg = test_config(format!("sqlite://{}", db_path.display()));

        let pool = connect_and_bootstrap(&cfg)
            .await
            .expect("bootstrap should succeed");

        let rows = sqlx::query("PRAGMA table_info(approver_credentials)")
            .fetch_all(&pool)
            .await
            .expect("pragma should work");

        let mut seen = std::collections::HashSet::new();
        for row in rows {
            seen.insert(
                row.try_get::<String, _>("name")
                    .expect("column name should parse"),
            );
        }

        assert!(seen.contains("algorithm"));
        assert!(seen.contains("public_key_format"));
        assert!(seen.contains("public_key_b64"));
    }

    #[test]
    fn new_id_uses_prefix() {
        let id = new_id("task");
        assert!(id.starts_with("task_"));
    }

    #[test]
    fn hash_helpers_are_deterministic() {
        assert_eq!(sha256_hex("abc"), sha256_hex("abc"));
        assert_eq!(sha256_hex_bytes(b"abc"), sha256_hex("abc"));
    }

    #[test]
    fn random_token_is_url_safe_without_padding() {
        let token = random_token(24);
        assert!(!token.contains('='));
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }
}
