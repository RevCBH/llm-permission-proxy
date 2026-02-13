use reqwest::Client;
use sqlx::SqlitePool;

use crate::{cf::CloudflareExecutor, config::Config};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: SqlitePool,
    pub http_client: Client,
    pub cf_executor: CloudflareExecutor,
}
