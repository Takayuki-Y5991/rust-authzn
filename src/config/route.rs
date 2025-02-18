use axum::{
  extract::{Json, State},
  routing::post,
  Router,
};
use tower_http::trace::TraceLayer;

use crate::{
  adapter::inbound::authentication_adapter::{AuthenticationAdapter, RedirectUrlApiRequest},
  port::inbound::authentication::AuthenticationPort,
};

async fn handle_redirect<T: AuthenticationPort + Clone>(
  State(adapter): State<AuthenticationAdapter<T>>,
  request: Json<RedirectUrlApiRequest>,
) -> impl axum::response::IntoResponse {
  adapter.redirect_uri(request).await
}

// async fn handle_callback<T: AuthenticationPort + Clone>(
//   State(adapter): State<AuthenticationAdapter<T>>,
//   request: Json<CallbackApiRequest>,
// ) -> impl axum::response::IntoResponse {
//   adapter.callback(request).await
// }

// async fn handle_verify<T: AuthenticationPort + Clone>(
//   State(adapter): State<AuthenticationAdapter<T>>,
//   Json(token): Json<String>,
// ) -> impl axum::response::IntoResponse {
//   adapter.verify_token(token).await
// }

// async fn handle_refresh<T: AuthenticationPort + Clone>(
//   State(adapter): State<AuthenticationAdapter<T>>,
//   Json(token): Json<String>,
// ) -> impl axum::response::IntoResponse {
//   adapter.refresh_token(token).await
// }

// async fn handle_user_info<T: AuthenticationPort + Clone>(
//   State(adapter): State<AuthenticationAdapter<T>>,
//   Json(token): Json<String>,
// ) -> impl axum::response::IntoResponse {
//   adapter.get_user_info(token).await
// }

// async fn handle_logout<T: AuthenticationPort + Clone>(
//   State(adapter): State<AuthenticationAdapter<T>>,
//   Json(token): Json<String>,
// ) -> impl axum::response::IntoResponse {
//   adapter.logout(token).await
// }

pub fn create_router<T>(auth_adapter: AuthenticationAdapter<T>) -> Router
where
  T: AuthenticationPort + Send + Sync + Clone + 'static,
{
  Router::new()
    .route("/auth/redirect", post(handle_redirect::<T>))
    // .route("/auth/callback", post(handle_callback::<T>))
    // .route("/auth/verify", post(handle_verify::<T>))
    // .route("/auth/refresh", post(handle_refresh::<T>))
    // .route("/auth/userinfo", get(handle_user_info::<T>))
    // .route("/auth/logout", post(handle_logout::<T>))
    .layer(TraceLayer::new_for_http())
    .with_state(auth_adapter)
}
