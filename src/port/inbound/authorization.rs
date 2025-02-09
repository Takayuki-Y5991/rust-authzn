use crate::core::domain::auth::error::AuthError;
use async_trait::async_trait;

#[async_trait]
pub trait AuthorizationPort {
  async fn exchange_token(&self, request: TokenRequest) -> Result<TokenResponse, AuthError>;

  async fn refresh_token(&self, request: RefreshTokenRequest) -> Result<TokenResponse, AuthError>;

  async fn revoke_token(&self, token: String) -> Result<(), AuthError>;
}

pub struct TokenRequest {
  pub grant_type: String,
  pub code: String,
  pub redirect_uri: String,
  pub client_id: String,
  pub code_verifier: String,
}

pub struct RefreshTokenRequest {
  pub grant_type: String,
  pub refresh_token: String,
  pub client_id: String,
}

pub struct TokenResponse {
  pub access_token: String,
  pub token_type: String,
  pub expires_in: u64,
  pub refresh_token: Option<String>,
  pub scope: String,
}
