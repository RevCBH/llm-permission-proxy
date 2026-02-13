use std::{str::FromStr, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{SqlitePool, sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions}};
use uuid::Uuid;

use crate::{config::Config, error::AppError};

pub async fn connect_and_migrate(config: &Config) -> Result<SqlitePool, AppError> {
    let options = SqliteConnectOptions::from_str(&config.database_url)
        .map_err(AppError::internal)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(AppError::internal)?;

    Ok(pool)
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
