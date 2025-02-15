use async_trait::async_trait;
use axum::{
  extract::State,
  http::StatusCode,
  response::{IntoResponse, Response},
  Json,
};
use serde::{Deserialize, Serialize};

use crate::{
  core::domain::auth::error::AuthError,
  port::inbound::authentication::{
    AuthAction, AuthenticationPort, CallbackRequest, CodeChallengeMethod, RedirectUrlRequest, RedirectUrlResponse,
    TokenResponse, TokenVerificationResponse, UserInfo,
  },
};

pub struct AuthenticationAdapter<T: AuthenticationPort> {
  auth_service: T,
}

impl<T: AuthenticationPort> AuthenticationAdapter<T> {
  pub fn new(auth_service: T) -> Self {
    Self { auth_service }
  }

  pub async fn redirect_url(&self, Json(request): Json<RedirectUrlApiRequest>) -> Result<impl IntoResponse, AppError> {
    let internal_request = RedirectUrlRequest {
      action: request.action,
      code_challenge: request.code_challenge,
      code_challenge_method: CodeChallengeMethod::S256,
    };

    let response = self.auth_service.generate_redirect_url(internal_request).await?;

    Ok(Json(RedirectUrlApiResponse {
      redirect_url: response.redirect_url,
      state: response.state,
    }))
  }

  pub async fn callback(&self, Json(request): Json<CallbackApiRequest>) -> Result<impl IntoResponse, AppError> {
    let internal_request = CallbackRequest {
      code: request.code,
      state: request.state,
      code_verifier: request.code_verifier,
    };

    let response = self.auth_service.handle_callback(internal_request).await?;
    Ok(Json(response))
  }

  pub async fn verify_token(&self, token: String) -> Result<impl IntoResponse, AppError> {
    let response = self.auth_service.verify_token(token).await?;
    Ok(Json(response))
  }

  pub async fn refresh_token(&self, refresh_token: String) -> Result<impl IntoResponse, AppError> {
    let response = self.auth_service.refresh_token(refresh_token).await?;
    Ok(Json(response))
  }

  pub async fn get_user_info(&self, access_token: String) -> Result<impl IntoResponse, AppError> {
    let response = self.auth_service.get_user_info(access_token).await?;
    Ok(Json(response))
  }

  pub async fn logout(&self, access_token: String) -> Result<impl IntoResponse, AppError> {
    self.auth_service.logout(access_token).await?;
    Ok(StatusCode::NO_CONTENT)
  }
}

#[derive(Debug, Deserialize)]
pub struct RedirectUrlApiRequest {
  pub action: AuthAction,
  pub code_challenge: String,
}

#[derive(Debug, Serialize)]
pub struct RedirectUrlApiResponse {
  pub redirect_url: String,
  pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct CallbackApiRequest {
  pub code: String,
  pub state: String,
  pub code_verifier: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
  #[error(transparent)]
  Auth(#[from] AuthError),
}

impl IntoResponse for AppError {
  fn into_response(self) -> Response {
    let (status, message) = match self {
      AppError::Auth(e) => (StatusCode::UNAUTHORIZED, e.to_string()),
    };

    (status, Json(ErrorResponse { message })).into_response()
  }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
  message: String,
}
