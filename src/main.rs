mod auth;
mod callbacks;
mod cf;
mod config;
mod db;
mod error;
mod handlers;
mod models;
mod policy;
mod state;
mod webauthn;

use axum::Router;
use reqwest::Client;
use tracing::info;

use crate::{callbacks::start_callback_worker, cf::CloudflareExecutor, config::Config, db::connect_and_bootstrap, handlers::router, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,llm_permission_proxy=info".to_string()),
        )
        .json()
        .init();

    let config = Config::from_env();
    let db = connect_and_bootstrap(&config).await?;
    let http_client = Client::builder().build()?;

    let cf_executor = CloudflareExecutor::new(
        config.cloudflare_api_token.clone(),
        config.cloudflare_api_base.clone(),
        http_client.clone(),
    );

    let state = AppState {
        config: config.clone(),
        db,
        http_client,
        cf_executor,
    };

    start_callback_worker(state.clone());

    let app: Router = router(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    info!(bind_addr = %config.bind_addr, "llm permission proxy listening");

    axum::serve(listener, app).await?;
    Ok(())
}
