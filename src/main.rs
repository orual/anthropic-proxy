use anyhow::Result;
use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api_key;
mod auth;
mod config;
mod device_flow;
mod error;
mod proxy;
mod session;
mod types;

use crate::{config::Config, session::SessionStore};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub session_store: Arc<SessionStore>,
    pub http_client: reqwest::Client,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "anthropic_proxy=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Arc::new(Config::from_env()?);
    info!("Starting Anthropic OAuth proxy server");

    // Initialize session store
    let session_store = Arc::new(SessionStore::new());

    // Log session storage location
    if let Some(data_dir) = dirs::data_local_dir() {
        let session_path = data_dir.join("anthropic-proxy").join("sessions.json");
        info!("Sessions will be persisted to: {}", session_path.display());
    }

    // Create HTTP client for proxying requests
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300)) // 5 minutes for long Claude responses
        .user_agent("Claude Code/1.0")
        .build()?;

    // Create app state
    let app_state = AppState {
        config,
        session_store,
        http_client,
    };

    // Build router
    let app = Router::new()
        // Auth routes
        .route("/auth/logout", post(auth::logout))
        .route("/auth/status", get(auth::status))
        .route("/auth/refresh", post(auth::refresh))
        // Device flow routes (the actual working OAuth flow)
        .route("/auth/device", get(device_flow::device_flow_page))
        .route("/auth/device/start", post(device_flow::start_device_flow))
        .route("/auth/device/submit", post(device_flow::submit_device_code))
        // API proxy routes
        .route(
            "/v1/*path",
            get(proxy::proxy_handler)
                .post(proxy::proxy_handler)
                .put(proxy::proxy_handler)
                .delete(proxy::proxy_handler)
                .patch(proxy::proxy_handler),
        )
        // Health check
        .route("/health", get(health_check))
        // Root redirect
        .route("/", get(root_handler))
        .with_state(app_state.clone())
        .layer(TraceLayer::new_for_http());

    // Start server
    let addr = app_state.config.server_address();
    info!("Listening on {}", addr);

    println!("\n🚀 Anthropic OAuth Proxy Server");
    println!("================================");
    println!(
        "Server running at: http://localhost:{}",
        app_state.config.port
    );
    println!("\nAuthentication (Device Flow):");
    println!(
        "  Visit: http://localhost:{}/auth/device",
        app_state.config.port
    );
    println!("\nAPI Endpoints:");
    println!(
        "  Status: http://localhost:{}/auth/status",
        app_state.config.port
    );
    println!(
        "  Health: http://localhost:{}/health",
        app_state.config.port
    );
    println!(
        "  Proxy:  http://localhost:{}/v1/*\n",
        app_state.config.port
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn root_handler() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "service": "Anthropic OAuth Proxy",
        "status": "running",
        "endpoints": {
            "login": "/auth/login",
            "status": "/auth/status",
            "health": "/health"
        },
        "note": "Visit /auth/login to authenticate with Anthropic"
    }))
}
