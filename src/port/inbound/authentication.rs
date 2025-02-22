use crate::core::domain::auth::error::AuthError;
use async_trait::async_trait;
use serde::Deserialize;

#[derive(Debug)]
pub struct RedirectUrlRequest {
  pub action: AuthAction,
  pub code_challenge: String,
  pub code_challenge_method: CodeChallengeMethod,
}

#[derive(Debug)]
pub struct RedirectUrlResponse {
  pub redirect_uri: String,
  pub state: String,
}

#[derive(Debug)]
pub struct CallbackRequest {
  pub code: String,
  pub state: String,
  pub code_verifier: String,
}

#[derive(Debug)]
pub struct TokenResponse {
  pub access_token: String,
  pub refresh_token: Option<String>,
  pub token_type: String,
  pub expires_in: u64,
  pub issued_at: String,
  pub issuer: String,
}

#[derive(Debug, Deserialize)]
pub enum AuthAction {
  Register,
  Login,
}

#[derive(Debug)]
pub enum CodeChallengeMethod {
  S256,
}

#[async_trait]
pub trait AuthenticationPort {
  /// Generate redirect URL for authentication
  async fn generate_redirect_uri(&self, request: RedirectUrlRequest) -> Result<RedirectUrlResponse, AuthError>;

  // /// Handle OAuth callback
  async fn handle_callback(&self, request: CallbackRequest) -> Result<TokenResponse, AuthError>;

  // /// Verify access token
  // async fn verify_token(&self, token: String) -> Result<TokenVerificationResponse, AuthError>;

  // /// Refresh access token
  // async fn refresh_token(&self, refresh_token: String) -> Result<TokenResponse, AuthError>;

  // /// Get user information
  // async fn get_user_info(&self, access_token: String) -> Result<UserInfo, AuthError>;

  // /// Logout user
  // async fn logout(&self, access_token: String) -> Result<(), AuthError>;
}

#[derive(Debug)]
pub struct TokenVerificationResponse {
  pub valid: bool,
  pub expires_in: Option<i64>,
}

#[derive(Debug)]
pub struct UserInfo {
  pub user_id: String,
  pub email: String,
  pub name: String,
  pub email_verified: bool,
  pub created_at: String,
  pub updated_at: String,
}
