use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: String,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub base_url: String,
    pub callback_max_retries: u32,
    pub callback_batch_size: u32,
    pub callback_worker_interval_secs: u64,
    pub approval_ttl_seconds: i64,
    pub approval_nonce_ttl_seconds: i64,
    pub webauthn_rp_id: String,
    pub webauthn_origin: String,
    pub cloudflare_api_token: Option<String>,
    pub cloudflare_api_base: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://data/proxy.db".to_string()),
            jwt_secret: env::var("JWT_SECRET").unwrap_or_else(|_| "dev-change-me".to_string()),
            jwt_issuer: env::var("JWT_ISSUER").unwrap_or_else(|_| "llm-permission-proxy".to_string()),
            jwt_audience: env::var("JWT_AUDIENCE").unwrap_or_else(|_| "llm-proxy-api".to_string()),
            base_url: env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string()),
            callback_max_retries: env::var("CALLBACK_MAX_RETRIES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            callback_batch_size: env::var("CALLBACK_BATCH_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50),
            callback_worker_interval_secs: env::var("CALLBACK_WORKER_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2),
            approval_ttl_seconds: env::var("APPROVAL_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600),
            approval_nonce_ttl_seconds: env::var("APPROVAL_NONCE_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(90),
            webauthn_rp_id: env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string()),
            webauthn_origin: env::var("WEBAUTHN_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            cloudflare_api_token: env::var("CLOUDFLARE_API_TOKEN").ok(),
            cloudflare_api_base: env::var("CLOUDFLARE_API_BASE")
                .unwrap_or_else(|_| "https://api.cloudflare.com/client/v4".to_string()),
        }
    }
}
