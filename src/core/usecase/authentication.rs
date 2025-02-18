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

#[derive(Clone)]
pub struct AuthenticationUseCase<T: OAuthProvider + Clone> {
  oauth_provider: T,
}

impl<T: OAuthProvider + Clone> AuthenticationUseCase<T> {
  pub fn new(oauth_provider: T) -> Self {
    Self { oauth_provider }
  }
}

#[async_trait]
impl<T: OAuthProvider + Clone + Send + Sync> AuthenticationPort for AuthenticationUseCase<T> {
  async fn generate_redirect_uri(&self, request: RedirectUrlRequest) -> Result<RedirectUrlResponse, AuthError> {
    let scopes = match request.action {
      crate::port::inbound::authentication::AuthAction::Register => {
        vec!["openid".to_string(), "profile".to_string(), "email".to_string()]
      }
      crate::port::inbound::authentication::AuthAction::Login => vec!["openid".to_string(), "profile".to_string()],
    };

    let (redirect_uri, state, _) = self.oauth_provider.generate_auth_url(scopes)?;

    Ok(RedirectUrlResponse {
      redirect_uri,
      state: state.secret().to_string(),
    })
  }

  // async fn handle_callback(&self, request: CallbackRequest) -> Result<TokenResponse, AuthError> {
  //   let provider_config = self.oauth_provider.get_provider_config().await?;

  //   let token_request = TokenRequest {
  //     code: request.code,
  //     code_verifier: request.code_verifier,
  //     grant_type: GrantType::AuthorizationCode,
  //     redirect_uri: provider_config.authorization_endpoint,
  //     client_id: "".to_string(), // This should come from configuration
  //   };

  //   let token_response = self.oauth_provider.get_token(token_request).await?;

  //   Ok(TokenResponse {
  //     access_token: token_response.access_token,
  //     refresh_token: token_response.refresh_token,
  //     token_type: token_response.token_type,
  //     expires_in: token_response.expires_in,
  //     issued_at: chrono::Utc::now().to_rfc3339(),
  //     issuer: provider_config.token_endpoint,
  //   })
  // }

  // async fn verify_token(&self, token: String) -> Result<TokenVerificationResponse, AuthError> {
  //   // In a real implementation, this would verify the token with the OAuth provider
  //   // For now, we'll return a simple response
  //   Ok(TokenVerificationResponse {
  //     valid: true,
  //     expires_in: Some(3600),
  //   })
  // }

  // async fn refresh_token(&self, refresh_token: String) -> Result<TokenResponse, AuthError> {
  //   let provider_config = self.oauth_provider.get_provider_config().await?;

  //   let refresh_request = RefreshTokenRequest {
  //     refresh_token,
  //     grant_type: GrantType::RefreshToken,
  //     client_id: "".to_string(), // This should come from configuration
  //   };

  //   let token_response = self.oauth_provider.refresh_token(refresh_request).await?;

  //   Ok(TokenResponse {
  //     access_token: token_response.access_token,
  //     refresh_token: token_response.refresh_token,
  //     token_type: token_response.token_type,
  //     expires_in: token_response.expires_in,
  //     issued_at: chrono::Utc::now().to_rfc3339(),
  //     issuer: provider_config.token_endpoint,
  //   })
  // }

  // async fn get_user_info(&self, _access_token: String) -> Result<UserInfo, AuthError> {
  //   // In a real implementation, this would fetch user info from the OAuth provider
  //   // For now, we'll return dummy data
  //   Ok(UserInfo {
  //     user_id: "dummy_id".to_string(),
  //     email: "dummy@example.com".to_string(),
  //     name: "Dummy User".to_string(),
  //     email_verified: true,
  //     created_at: chrono::Utc::now().to_rfc3339(),
  //     updated_at: chrono::Utc::now().to_rfc3339(),
  //   })
  // }

  // async fn logout(&self, access_token: String) -> Result<(), AuthError> {
  //   self.oauth_provider.revoke_token(access_token).await
  // }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    adapter::outbound::okka_adapter::OkkaOAuthProvider,
    port::inbound::authentication::{AuthAction, CodeChallengeMethod},
  };

  static TEST_AUTH_URL: &str = "https://example.com/auth";
  static TEST_TOKEN_URL: &str = "https://example.com/token";
  static TEST_CLIENT_ID: &str = "test_client_id";
  static TEST_CLIENT_SECRET: &str = "test_client_secret";
  static TEST_REDIRECT_URL: &str = "https://example.com/callback";

  #[tokio::test]
  async fn test_generate_redirect_uri() {
    let provider = OkkaOAuthProvider::new(
      TEST_AUTH_URL.to_string(),
      TEST_TOKEN_URL.to_string(),
      TEST_CLIENT_ID.to_string(),
      Some(TEST_CLIENT_SECRET.to_string()),
      TEST_REDIRECT_URL.to_string(),
    )
    .unwrap();

    let auth_use_case = AuthenticationUseCase::new(provider);

    let request = RedirectUrlRequest {
      action: AuthAction::Login,
      code_challenge: "test_challenge".to_string(),
      code_challenge_method: CodeChallengeMethod::S256,
    };

    let result = auth_use_case.generate_redirect_uri(request).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    assert!(!response.redirect_uri.is_empty());
    assert!(!response.state.is_empty());
    assert!(response.redirect_uri.contains(TEST_AUTH_URL));
    assert!(response.redirect_uri.contains("scope=openid+profile"));
  }
}
