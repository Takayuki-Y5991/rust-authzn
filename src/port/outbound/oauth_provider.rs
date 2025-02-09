use crate::core::domain::auth::error::AuthError;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub enum GrantType {
  AuthorizationCode,
  RefreshToken,
}

impl GrantType {
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::AuthorizationCode => "authorization_code",
      Self::RefreshToken => "refresh_token",
    }
  }
}

#[derive(Debug, Clone)]
pub struct TokenRequest {
  pub grant_type: GrantType,
  pub code: String,
  pub redirect_uri: String,
  pub client_id: String,
  pub code_verifier: String,
}

#[derive(Debug, Clone)]
pub struct RefreshTokenRequest {
  pub grant_type: GrantType, // 常にRefreshToken
  pub refresh_token: String,
  pub client_id: String,
}

#[derive(Debug, Clone)]
pub struct TokenResponse {
  pub access_token: String,
  pub token_type: String,
  pub expires_in: u64,
  pub refresh_token: Option<String>,
  pub scope: String,
}

#[async_trait]
pub trait OAuthProvider {
  async fn get_token(&self, request: TokenRequest) -> Result<TokenResponse, AuthError>;

  async fn refresh_token(&self, request: RefreshTokenRequest) -> Result<TokenResponse, AuthError>;

  async fn revoke_token(&self, token: String) -> Result<(), AuthError>;

  async fn get_provider_config(&self) -> Result<ProviderConfig, AuthError>;
}

#[derive(Debug, Clone)]
pub struct ProviderConfig {
  pub authorization_endpoint: String,
  pub token_endpoint: String,
  pub revocation_endpoint: Option<String>,
}
