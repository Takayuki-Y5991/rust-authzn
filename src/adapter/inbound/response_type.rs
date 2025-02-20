use axum::{
  http::StatusCode,
  response::{IntoResponse, Response},
  Json,
};
use serde::Serialize;

use crate::core::domain::auth::error::AuthError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
  #[error(transparent)]
  Auth(#[from] AuthError),
  #[error("Validation error: {0}")]
  Validation(String),
}

impl IntoResponse for AppError {
  fn into_response(self) -> Response {
    let (status, message) = match self {
      AppError::Auth(e) => (StatusCode::UNAUTHORIZED, e.to_string()),
      AppError::Validation(e) => (StatusCode::BAD_REQUEST, e),
    };

    (status, Json(ErrorResponse { message })).into_response()
  }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
  message: String,
}
