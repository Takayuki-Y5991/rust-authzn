use axum::{
  http::{header, HeaderValue},
  response::IntoResponse,
  Json,
};
use cookie::{time, Cookie, SameSite};
use serde::{Deserialize, Serialize};

use crate::port::inbound::authentication::{AuthAction, AuthenticationPort, CodeChallengeMethod, RedirectUrlRequest};

use super::response_type::AppError;

#[derive(Clone)]
pub struct AuthenticationAdapter<T: AuthenticationPort + Clone> {
  auth_usecase: T,
}

impl<T: AuthenticationPort + Clone> AuthenticationAdapter<T> {
  pub fn new(auth_usecase: T) -> Self {
    Self { auth_usecase }
  }

  pub async fn redirect_uri(&self, Json(request): Json<RedirectUrlApiRequest>) -> Result<impl IntoResponse, AppError> {
    if request.code_challenge.len() < 43 || request.code_challenge.len() > 128 {
      return Err(AppError::Validation("Invalid code challenge length".to_string()));
    }

    let internal_request = RedirectUrlRequest {
      action: request.action,
      code_challenge: request.code_challenge,
      code_challenge_method: CodeChallengeMethod::S256,
    };

    let response = self.auth_usecase.generate_redirect_uri(internal_request).await?;

    let state = response.state.clone();

    let json_response = Json(RedirectUrlApiResponse {
      redirect_uri: response.redirect_uri,
      state: state.clone(),
      expires_in: 600,
    });
    let cookie = Cookie::build(("auth_state", state))
      .path("/")
      .secure(true)
      .http_only(true)
      .max_age(time::Duration::seconds(600))
      .same_site(SameSite::Lax)
      .build();

    let mut res = json_response.into_response();

    if let Ok(cookie_value) = HeaderValue::from_str(&cookie.to_string()) {
      res.headers_mut().insert(header::SET_COOKIE, cookie_value);
    }

    Ok(res)
  }

  // pub async fn callback(&self, Json(request): Json<CallbackApiRequest>) -> Result<impl IntoResponse, AppError> {
  //   let internal_request = CallbackRequest {
  //     code: request.code,
  //     state: request.state,
  //     code_verifier: request.code_verifier,
  //   };

  //   let response = self.auth_service.handle_callback(internal_request).await?;
  //   Ok(Json(response))
  // }

  // pub async fn verify_token(&self, token: String) -> Result<impl IntoResponse, AppError> {
  //   let response = self.auth_service.verify_token(token).await?;
  //   Ok(Json(response))
  // }

  // pub async fn refresh_token(&self, refresh_token: String) -> Result<impl IntoResponse, AppError> {
  //   let response = self.auth_service.refresh_token(refresh_token).await?;
  //   Ok(Json(response))
  // }

  // pub async fn get_user_info(&self, access_token: String) -> Result<impl IntoResponse, AppError> {
  //   let response = self.auth_service.get_user_info(access_token).await?;
  //   Ok(Json(response))
  // }

  // pub async fn logout(&self, access_token: String) -> Result<impl IntoResponse, AppError> {
  //   self.auth_service.logout(access_token).await?;
  //   Ok(StatusCode::NO_CONTENT)
  // }
}

#[derive(Debug, Deserialize)]
pub struct RedirectUrlApiRequest {
  pub action: AuthAction,
  pub code_challenge: String,
  pub redirect_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RedirectUrlApiResponse {
  pub redirect_uri: String,
  pub state: String,
  pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct CallbackApiRequest {
  pub code: String,
  pub state: String,
  pub code_verifier: String,
}
