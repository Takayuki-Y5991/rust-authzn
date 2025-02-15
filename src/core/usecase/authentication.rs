use crate::{
  core::domain::auth::error::AuthError,
  port::{
    inbound::authentication::{
      AuthenticationPort, CallbackRequest, RedirectUrlRequest, RedirectUrlResponse, TokenResponse,
      TokenVerificationResponse, UserInfo,
    },
    outbound::oauth_provider::{GrantType, OAuthProvider, RefreshTokenRequest, TokenRequest},
  },
};
use async_trait::async_trait;

pub struct AuthenticationUseCase<T: OAuthProvider> {
  oauth_provider: T,
}

impl<T: OAuthProvider> AuthenticationUseCase<T> {
  pub fn new(oauth_provider: T) -> Self {
    Self { oauth_provider }
  }
}

#[async_trait]
impl<T: OAuthProvider + Send + Sync> AuthenticationPort for AuthenticationUseCase<T> {
  async fn generate_redirect_url(&self, request: RedirectUrlRequest) -> Result<RedirectUrlResponse, AuthError> {
    let scopes = match request.action {
      crate::port::inbound::authentication::AuthAction::Register => {
        vec!["openid".to_string(), "profile".to_string(), "email".to_string()]
      }
      crate::port::inbound::authentication::AuthAction::Login => vec!["openid".to_string(), "profile".to_string()],
    };

    let (redirect_url, state, _) = self.oauth_provider.generate_auth_url(scopes)?;

    Ok(RedirectUrlResponse {
      redirect_url,
      state: state.secret().to_string(),
    })
  }

  async fn handle_callback(&self, request: CallbackRequest) -> Result<TokenResponse, AuthError> {
    let provider_config = self.oauth_provider.get_provider_config().await?;

    let token_request = TokenRequest {
      code: request.code,
      code_verifier: request.code_verifier,
      grant_type: GrantType::AuthorizationCode,
      redirect_uri: provider_config.authorization_endpoint,
      client_id: "".to_string(), // This should come from configuration
    };

    let token_response = self.oauth_provider.get_token(token_request).await?;

    Ok(TokenResponse {
      access_token: token_response.access_token,
      refresh_token: token_response.refresh_token,
      token_type: token_response.token_type,
      expires_in: token_response.expires_in,
      issued_at: chrono::Utc::now().to_rfc3339(),
      issuer: provider_config.token_endpoint,
    })
  }

  async fn verify_token(&self, token: String) -> Result<TokenVerificationResponse, AuthError> {
    // In a real implementation, this would verify the token with the OAuth provider
    // For now, we'll return a simple response
    Ok(TokenVerificationResponse {
      valid: true,
      expires_in: Some(3600),
    })
  }

  async fn refresh_token(&self, refresh_token: String) -> Result<TokenResponse, AuthError> {
    let provider_config = self.oauth_provider.get_provider_config().await?;

    let refresh_request = RefreshTokenRequest {
      refresh_token,
      grant_type: GrantType::RefreshToken,
      client_id: "".to_string(), // This should come from configuration
    };

    let token_response = self.oauth_provider.refresh_token(refresh_request).await?;

    Ok(TokenResponse {
      access_token: token_response.access_token,
      refresh_token: token_response.refresh_token,
      token_type: token_response.token_type,
      expires_in: token_response.expires_in,
      issued_at: chrono::Utc::now().to_rfc3339(),
      issuer: provider_config.token_endpoint,
    })
  }

  async fn get_user_info(&self, _access_token: String) -> Result<UserInfo, AuthError> {
    // In a real implementation, this would fetch user info from the OAuth provider
    // For now, we'll return dummy data
    Ok(UserInfo {
      user_id: "dummy_id".to_string(),
      email: "dummy@example.com".to_string(),
      name: "Dummy User".to_string(),
      email_verified: true,
      created_at: chrono::Utc::now().to_rfc3339(),
      updated_at: chrono::Utc::now().to_rfc3339(),
    })
  }

  async fn logout(&self, access_token: String) -> Result<(), AuthError> {
    self.oauth_provider.revoke_token(access_token).await
  }
}
