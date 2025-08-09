
mod model;
mod repository;
mod config;
mod util;
mod service;
mod handler;
mod router;
mod app;
mod dto;
mod middlewares;

use dotenv::dotenv;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;





#[tokio::main]
async fn main() {
    // Initialize tracing with detailed logging
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("debug"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_level(true)
        .with_ansi(true)
        .init();

    info!("🚀 Starting Elhaiba Backend Application");

    // Load environment variables from .env file
    match dotenv() {
        Ok(_) => info!("✅ Successfully loaded .env file"),
        Err(e) => warn!("⚠️ Failed to load .env file: {} (using system env vars)", e),
    }

    // Create and start the App
    let app = crate::app::app::App::new().await;
    app.start().await;
}
