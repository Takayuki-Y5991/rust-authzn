use axum::{
  extract::State,
  routing::{get, post},
  Router,
};
use rust_authzn::config::config::Config;

use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
  // Initialize tracing
  tracing_subscriber::registry()
    .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
    .with(tracing_subscriber::fmt::layer())
    .init();

  // Load configuration
  let config = Config::from_env();

  // Initialize authentication service
  let auth_service = AuthenticationService::new();
  let auth_adapter = AuthenticationAdapter::new(auth_service);

  // Build router with routes
  let app = Router::new()
    .route("/auth/redirect", post(auth_adapter.redirect_url))
    .route("/auth/callback", post(auth_adapter.callback))
    .route("/auth/verify", post(auth_adapter.verify_token))
    .route("/auth/refresh", post(auth_adapter.refresh_token))
    .route("/auth/userinfo", get(auth_adapter.get_user_info))
    .route("/auth/logout", post(auth_adapter.logout))
    .layer(TraceLayer::new_for_http())
    .with_state(auth_adapter);

  // Get the address to bind to
  let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
  let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

  tracing::info!("listening on {}", listener.local_addr().unwrap());

  axum::serve(listener, app).await.unwrap();
}
