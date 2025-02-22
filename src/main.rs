use rust_authzn::{
  adapter::{
    inbound::authentication_adapter::AuthenticationAdapter,
    outbound::{okka_adapter::OkkaOAuthProvider, redis_adapter::RedisCacheAdapter},
  },
  config::{envs::Config, route::create_router},
  core::usecase::authentication::AuthenticationUseCase,
};

use std::net::SocketAddr;
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

  // Initialize OAuth provider
  let oauth_provider = OkkaOAuthProvider::new(
    &config.oauth.auth_url,
    &config.oauth.token_url,
    &config.oauth.client_id,
    Some(&config.oauth.client_secret),
    &config.oauth.redirect_url,
    &config.oauth.issuer,
  )
  .expect("Failed to initialize OAuth provider");

  let redis_cache =
    RedisCacheAdapter::new(&config.redis.url, &config.redis.prefix).expect("Failed to initialize Redis cache");

  // Initialize authentication usecase and adapter
  let auth_usecase = AuthenticationUseCase::new(oauth_provider, redis_cache);
  let auth_adapter = AuthenticationAdapter::new(auth_usecase);

  // Build router with routes
  let app = create_router(auth_adapter);

  // Get the address to bind to
  let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
  let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

  tracing::info!("listening on {}", listener.local_addr().unwrap());

  axum::serve(listener, app).await.unwrap();
}
