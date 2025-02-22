use crate::{
  core::domain::auth::{constants::AuthorizationConstants, error::AuthError},
  port::{
    inbound::authentication::{
      AuthenticationPort, CallbackRequest, RedirectUrlRequest, RedirectUrlResponse, TokenResponse,
    },
    outbound::{
      cache_provider::CacheProvider,
      oauth_provider::{GrantType, OAuthProvider, TokenRequest},
    },
  },
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use super::utils::time_utils::now_time_secs;

impl From<Box<dyn std::error::Error>> for AuthError {
  fn from(error: Box<dyn std::error::Error>) -> Self {
    AuthError::ProviderError(error.to_string())
  }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for AuthError {
  fn from(error: Box<dyn std::error::Error + Send + Sync>) -> Self {
    AuthError::ProviderError(error.to_string())
  }
}

#[derive(Serialize, Deserialize)]
struct PkceSession {
  code_verifier: String,
  expires_at: u64,
}

#[derive(Clone)]
pub struct AuthenticationUseCase<T: OAuthProvider + Clone, C: CacheProvider + Clone + Send + Sync> {
  oauth_provider: T,
  cache_provider: C,
}

impl<T: OAuthProvider + Clone, C: CacheProvider + Clone + Send + Sync> AuthenticationUseCase<T, C> {
  pub fn new(oauth_provider: T, cache_provider: C) -> Self {
    Self {
      oauth_provider,
      cache_provider,
    }
  }
}

#[async_trait]
impl<T: OAuthProvider + Clone + Send + Sync, C: CacheProvider + Clone + Send + Sync> AuthenticationPort
  for AuthenticationUseCase<T, C>
{
  async fn generate_redirect_uri(&self, request: RedirectUrlRequest) -> Result<RedirectUrlResponse, AuthError> {
    let scopes = match request.action {
      crate::port::inbound::authentication::AuthAction::Register => {
        vec!["openid".to_string(), "profile".to_string(), "email".to_string()]
      }
      crate::port::inbound::authentication::AuthAction::Login => vec!["openid".to_string(), "profile".to_string()],
    };

    let (redirect_uri, state, pkce_verifier) = self.oauth_provider.generate_auth_url(scopes)?;

    let now_secs = now_time_secs().map_err(|err| AuthError::UnexpectedError(err.to_string()))?;

    let session = PkceSession {
      code_verifier: pkce_verifier.secret().to_string(),
      expires_at: now_secs + AuthorizationConstants::PKCE_SESSION_TTL_SECONDS,
    };

    let key = AuthorizationConstants::pkce_session_key(state.secret());

    self
      .cache_provider
      .store(&key, &session, AuthorizationConstants::PKCE_SESSION_TTL_SECONDS)
      .await
      .map_err(|e| AuthError::ProviderError(format!("Failed to store PKCE session: {}", e)))?;

    Ok(RedirectUrlResponse {
      redirect_uri,
      state: state.secret().to_string(),
    })
  }

  async fn handle_callback(&self, request: CallbackRequest) -> Result<TokenResponse, AuthError> {
    // 1. Retrieve the PKCE session from the cache
    let session_key = AuthorizationConstants::pkce_session_key(&request.state);
    let pkce_session: PkceSession = self.cache_provider.get(&session_key).await?.ok_or(AuthError::InvalidState)?;

    // 2. verify the code verifier
    if pkce_session.code_verifier != request.code_verifier {
      return Err(AuthError::InvalidCodeVerifier);
    }

    // 3. verify the session expiration
    let now = now_time_secs().map_err(|err| AuthError::UnexpectedError(err.to_string()))?;
    if now > pkce_session.expires_at {
      return Err(AuthError::SessionExpired);
    }

    // 4. Delete the PKCE session from the cache
    let _ = self.cache_provider.remove(&session_key).await;

    // 5. fetch provider config
    let provider_config = self.oauth_provider.get_provider_config().await?;

    let token_request = TokenRequest {
      code: request.code,
      grant_type: GrantType::AuthorizationCode,
      client_id: provider_config.client_id,
      redirect_uri: provider_config.redirect_uri,
      code_verifier: pkce_session.code_verifier,
    };

    let token_response = self.oauth_provider.get_token(token_request).await?;

    Ok(TokenResponse {
      access_token: token_response.access_token,
      refresh_token: token_response.refresh_token,
      token_type: token_response.token_type,
      expires_in: token_response.expires_in,
      issued_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string(),
      issuer: provider_config.issuer,
    })
  }

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
  use crate::core::usecase::utils::time_utils::test_utils::{reset_mock_time, set_mock_time};
  use crate::port::outbound::oauth_provider::{RefreshTokenRequest, TokenRequest, TokenResponse as OAuthTokenResponse};
  use crate::port::{
    inbound::authentication::{AuthAction, CodeChallengeMethod},
    outbound::oauth_provider::ProviderConfig,
  };
  use oauth2::{CsrfToken, PkceCodeVerifier};
  use serde::de::DeserializeOwned;
  use std::collections::HashMap;
  use std::sync::{Arc, Mutex};

  #[derive(Clone)]
  struct MockOAuthProvider {
    generate_auth_url_result: Arc<Mutex<Result<(String, CsrfToken, PkceCodeVerifier), AuthError>>>,
    received_scopes: Arc<Mutex<Option<Vec<String>>>>,
    get_token_result: Arc<Mutex<Result<OAuthTokenResponse, AuthError>>>,
    provider_config: Arc<Mutex<Result<ProviderConfig, AuthError>>>,
  }

  #[async_trait]
  impl OAuthProvider for MockOAuthProvider {
    fn generate_auth_url(&self, scopes: Vec<String>) -> Result<(String, CsrfToken, PkceCodeVerifier), AuthError> {
      *self.received_scopes.lock().unwrap() = Some(scopes);
      let result_guard = self.generate_auth_url_result.lock().unwrap();
      match &*result_guard {
        Ok((redirect_uri, csrf_token, pkce_code_verifier)) => Ok((
          redirect_uri.clone(),
          csrf_token.clone(),
          PkceCodeVerifier::new(pkce_code_verifier.secret().to_string()),
        )),
        Err(err) => Err(err.clone()),
      }
    }

    async fn get_token(&self, _request: TokenRequest) -> Result<OAuthTokenResponse, AuthError> {
      self.get_token_result.lock().unwrap().clone()
    }

    async fn refresh_token(&self, _request: RefreshTokenRequest) -> Result<OAuthTokenResponse, AuthError> {
      unimplemented!("Not used in this test")
    }

    async fn revoke_token(&self, _token: String) -> Result<(), AuthError> {
      unimplemented!("Not used in this test")
    }

    async fn get_provider_config(&self) -> Result<ProviderConfig, AuthError> {
      self.provider_config.lock().unwrap().clone()
    }
  }

  #[derive(Clone)]
  struct MockCacheProvider {
    store_result: Arc<Mutex<Result<(), Box<dyn std::error::Error + Send + Sync>>>>,
    store_calls: Arc<Mutex<Vec<(String, u64)>>>,
    stored_sessions: Arc<Mutex<HashMap<String, PkceSession>>>,
    remove_calls: Arc<Mutex<Vec<String>>>,
  }

  impl MockCacheProvider {
    fn new() -> Self {
      let mut sessions = HashMap::new();
      // デフォルトのテストセッションを登録
      sessions.insert(
        AuthorizationConstants::pkce_session_key("test_state"),
        PkceSession {
          code_verifier: "test_verifier".to_string(),
          expires_at: TEST_TIMESTAMP + AuthorizationConstants::PKCE_SESSION_TTL_SECONDS - 1,
        },
      );

      Self {
        store_result: Arc::new(Mutex::new(Ok(()))),
        store_calls: Arc::new(Mutex::new(Vec::new())),
        stored_sessions: Arc::new(Mutex::new(sessions)),
        remove_calls: Arc::new(Mutex::new(Vec::new())),
      }
    }
  }

  #[async_trait]
  impl CacheProvider for MockCacheProvider {
    async fn store<T: Serialize + Send + Sync>(
      &self,
      key: &str,
      data: &T,
      ttl: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
      self.store_calls.lock().unwrap().push((key.to_string(), ttl));

      if let Ok(session) = serde_json::from_value::<PkceSession>(serde_json::to_value(data)?) {
        self.stored_sessions.lock().unwrap().insert(key.to_string(), session);
      }
      let result = self.store_result.lock().unwrap();
      match *result {
        Ok(()) => Ok(()),
        Err(ref e) => Err(Box::<dyn std::error::Error + Send + Sync>::from(e.to_string())),
      }
    }

    async fn get<T: DeserializeOwned + Send + Sync>(&self, key: &str) -> Result<Option<T>, Box<dyn std::error::Error>> {
      let sessions = self.stored_sessions.lock().unwrap();
      if let Some(session) = sessions.get(key) {
        Ok(Some(serde_json::from_value(serde_json::to_value(session)?)?))
      } else {
        Ok(None)
      }
    }

    async fn remove(&self, key: &str) -> Result<(), Box<dyn std::error::Error>> {
      self.remove_calls.lock().unwrap().push(key.to_string());
      self.stored_sessions.lock().unwrap().remove(key);
      Ok(())
    }
  }

  const TEST_TIMESTAMP: u64 = 1678900000;

  #[tokio::test]
  async fn test_generate_redirect_uri_login_success() {
    // Create Mocks
    let mock_oauth = MockOAuthProvider {
      generate_auth_url_result: Arc::new(Mutex::new(Ok((
        "https://auth.example.com/authorize?response_type=code".to_string(),
        CsrfToken::new("test_state_123".to_string()),
        PkceCodeVerifier::new("test_code_verifier_456".to_string()),
      )))),
      received_scopes: Arc::new(Mutex::new(None)),
      get_token_result: Arc::new(Mutex::new(Ok(OAuthTokenResponse {
        access_token: "test_access_token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some("test_refresh_token".to_string()),
        scope: "openid profile".to_string(),
      }))),
      provider_config: Arc::new(Mutex::new(Ok(ProviderConfig {
        authorization_endpoint: "https://auth.example.com/authorize".to_string(),
        token_endpoint: "https://auth.example.com/token".to_string(),
        revocation_endpoint: Some("https://auth.example.com/revoke".to_string()),
        client_id: "test_client_id".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        issuer: "https://auth.example.com".to_string(),
      }))),
    };

    let mock_cache = MockCacheProvider::new();

    // Generate Usecase
    let use_case = AuthenticationUseCase::new(mock_oauth.clone(), mock_cache.clone());

    set_mock_time(TEST_TIMESTAMP);

    let request = RedirectUrlRequest {
      action: AuthAction::Login,
      code_challenge: "challenge_abc".to_string(),
      code_challenge_method: CodeChallengeMethod::S256,
    };

    let result = use_case.generate_redirect_uri(request).await;

    reset_mock_time();

    assert!(result.is_ok(), "Expected success but got error: {:?}", result.err());

    let actual = result.unwrap();

    assert_eq!(
      actual.redirect_uri,
      "https://auth.example.com/authorize?response_type=code"
    );
    assert_eq!(actual.state, "test_state_123");
    let scopes = mock_oauth.received_scopes.lock().unwrap().clone().unwrap();
    assert_eq!(scopes, vec!["openid".to_string(), "profile".to_string()]);

    let store_calls = mock_cache.store_calls.lock().unwrap();
    assert_eq!(store_calls.len(), 1, "Cache store should be called exactly once");

    let (key, ttl) = &store_calls[0];
    assert_eq!(key, &AuthorizationConstants::pkce_session_key("test_state_123"));
    assert_eq!(*ttl, AuthorizationConstants::PKCE_SESSION_TTL_SECONDS);
  }

  #[tokio::test]
  async fn test_generate_redirect_uri_register_success() {
    let mock_oauth = MockOAuthProvider {
      generate_auth_url_result: Arc::new(Mutex::new(Ok((
        "https://auth.example.com/authorize?response_type=code".to_string(),
        CsrfToken::new("test_state_register".to_string()),
        PkceCodeVerifier::new("test_code_verifier_register".to_string()),
      )))),
      received_scopes: Arc::new(Mutex::new(None)),
      get_token_result: Arc::new(Mutex::new(Ok(OAuthTokenResponse {
        access_token: "test_access_token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some("test_refresh_token".to_string()),
        scope: "openid profile email".to_string(),
      }))),
      provider_config: Arc::new(Mutex::new(Ok(ProviderConfig {
        authorization_endpoint: "https://auth.example.com/authorize".to_string(),
        token_endpoint: "https://auth.example.com/token".to_string(),
        revocation_endpoint: Some("https://auth.example.com/revoke".to_string()),
        client_id: "test_client_id".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        issuer: "https://auth.example.com".to_string(),
      }))),
    };

    let mock_cache = MockCacheProvider::new();
    let use_case = AuthenticationUseCase::new(mock_oauth.clone(), mock_cache.clone());

    set_mock_time(TEST_TIMESTAMP);

    let request = RedirectUrlRequest {
      action: AuthAction::Register,
      code_challenge: "challenge_def".to_string(),
      code_challenge_method: CodeChallengeMethod::S256,
    };

    let actual = use_case.generate_redirect_uri(request).await;

    reset_mock_time();

    assert!(actual.is_ok());

    let scopes = mock_oauth.received_scopes.lock().unwrap().clone().unwrap();
    assert_eq!(
      scopes,
      vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
      "Register action should include email scope"
    );
  }

  #[tokio::test]
  async fn test_generate_redirect_uri_oauth_error() {
    let mock_oauth = MockOAuthProvider {
      generate_auth_url_result: Arc::new(Mutex::new(Err(AuthError::ConfigurationError(
        "Invalid OAuth configuration".to_string(),
      )))),
      received_scopes: Arc::new(Mutex::new(None)),
      get_token_result: Arc::new(Mutex::new(Ok(OAuthTokenResponse {
        access_token: "test_access_token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some("test_refresh_token".to_string()),
        scope: "openid profile".to_string(),
      }))),
      provider_config: Arc::new(Mutex::new(Ok(ProviderConfig {
        authorization_endpoint: "https://auth.example.com/authorize".to_string(),
        token_endpoint: "https://auth.example.com/token".to_string(),
        revocation_endpoint: Some("https://auth.example.com/revoke".to_string()),
        client_id: "test_client_id".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        issuer: "https://auth.example.com".to_string(),
      }))),
    };
    let mock_cache = MockCacheProvider::new();

    let use_case = AuthenticationUseCase::new(mock_oauth, mock_cache);

    let request = RedirectUrlRequest {
      action: AuthAction::Login,
      code_challenge: "challenge_xyz".to_string(),
      code_challenge_method: CodeChallengeMethod::S256,
    };

    let actual = use_case.generate_redirect_uri(request).await;

    assert!(actual.is_err());
    match actual.unwrap_err() {
      AuthError::ConfigurationError(msg) => {
        assert_eq!(msg, "Invalid OAuth configuration");
      }
      err => panic!("Expected ConfigurationError but got: {:?}", err),
    }
  }

  #[tokio::test]
  async fn test_generate_redirect_uri_cache_error() {
    let mock_oauth = MockOAuthProvider {
      generate_auth_url_result: Arc::new(Mutex::new(Ok((
        "https://auth.example.com/authorize".to_string(),
        CsrfToken::new("test_state".to_string()),
        PkceCodeVerifier::new("test_verifier".to_string()),
      )))),
      received_scopes: Arc::new(Mutex::new(None)),
      get_token_result: Arc::new(Mutex::new(Ok(OAuthTokenResponse {
        access_token: "test_access_token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some("test_refresh_token".to_string()),
        scope: "openid profile".to_string(),
      }))),
      provider_config: Arc::new(Mutex::new(Ok(ProviderConfig {
        authorization_endpoint: "https://auth.example.com/authorize".to_string(),
        token_endpoint: "https://auth.example.com/token".to_string(),
        revocation_endpoint: Some("https://auth.example.com/revoke".to_string()),
        client_id: "test_client_id".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        issuer: "https://auth.example.com".to_string(),
      }))),
    };

    let mock_cache = MockCacheProvider::new();

    *mock_cache.store_result.lock().unwrap() = Err("Redis connection failed".into());

    let use_case = AuthenticationUseCase::new(mock_oauth, mock_cache);

    set_mock_time(TEST_TIMESTAMP);

    let request = RedirectUrlRequest {
      action: AuthAction::Login,
      code_challenge: "test_challenge".to_string(),
      code_challenge_method: CodeChallengeMethod::S256,
    };

    let actual = use_case.generate_redirect_uri(request).await;

    reset_mock_time();

    assert!(actual.is_err());
    match actual.unwrap_err() {
      AuthError::ProviderError(msg) => {
        assert!(msg.contains("Failed to store PKCE session"));
        assert!(msg.contains("Redis connection failed"));
      }
      err => panic!("Expected ProviderError but got: {:?}", err),
    }
  }

  #[tokio::test]
  async fn test_handle_callback_success() {
    let mock_oauth = MockOAuthProvider {
      generate_auth_url_result: Arc::new(Mutex::new(Ok((
        "https://auth.example.com/authorize".to_string(),
        CsrfToken::new("test_state".to_string()),
        PkceCodeVerifier::new("test_verifier".to_string()),
      )))),
      received_scopes: Arc::new(Mutex::new(None)),
      get_token_result: Arc::new(Mutex::new(Ok(OAuthTokenResponse {
        access_token: "test_access_token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some("test_refresh_token".to_string()),
        scope: "openid profile".to_string(),
      }))),
      provider_config: Arc::new(Mutex::new(Ok(ProviderConfig {
        authorization_endpoint: "https://auth.example.com/authorize".to_string(),
        token_endpoint: "https://auth.example.com/token".to_string(),
        revocation_endpoint: Some("https://auth.example.com/revoke".to_string()),
        client_id: "test_client_id".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        issuer: "https://auth.example.com".to_string(),
      }))),
    };

    let mock_cache = MockCacheProvider::new();
    set_mock_time(TEST_TIMESTAMP);

    let use_case = AuthenticationUseCase::new(mock_oauth, mock_cache);

    let request = CallbackRequest {
      code: "test_code".to_string(),
      state: "test_state".to_string(),
      code_verifier: "test_verifier".to_string(),
    };

    let result = use_case.handle_callback(request).await;
    reset_mock_time();

    assert!(result.is_ok(), "Expected success but got error: {:?}", result.err());

    let token_response = result.unwrap();
    assert_eq!(token_response.access_token, "test_access_token");
    assert_eq!(token_response.token_type, "Bearer");
    assert_eq!(token_response.expires_in, 3600);
    assert_eq!(token_response.refresh_token, Some("test_refresh_token".to_string()));
    assert_eq!(token_response.issuer, "https://auth.example.com");
  }

  #[tokio::test]
  async fn test_handle_callback_invalid_state() {
    let mock_oauth = MockOAuthProvider {
      generate_auth_url_result: Arc::new(Mutex::new(Ok((
        "https://auth.example.com/authorize".to_string(),
        CsrfToken::new("test_state".to_string()),
        PkceCodeVerifier::new("test_verifier".to_string()),
      )))),
      received_scopes: Arc::new(Mutex::new(None)),
      get_token_result: Arc::new(Mutex::new(Ok(OAuthTokenResponse {
        access_token: "test_access_token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some("test_refresh_token".to_string()),
        scope: "openid profile".to_string(),
      }))),
      provider_config: Arc::new(Mutex::new(Ok(ProviderConfig {
        authorization_endpoint: "https://auth.example.com/authorize".to_string(),
        token_endpoint: "https://auth.example.com/token".to_string(),
        revocation_endpoint: Some("https://auth.example.com/revoke".to_string()),
        client_id: "test_client_id".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        issuer: "https://auth.example.com".to_string(),
      }))),
    };

    let mock_cache = MockCacheProvider::new();

    let use_case = AuthenticationUseCase::new(mock_oauth, mock_cache);

    let request = CallbackRequest {
      code: "test_code".to_string(),
      state: "invalid_state".to_string(),
      code_verifier: "test_verifier".to_string(),
    };

    let result = use_case.handle_callback(request).await;

    assert!(result.is_err());
    match result.unwrap_err() {
      AuthError::InvalidState => {}
      err => panic!("Expected InvalidState but got: {:?}", err),
    }
  }

  #[tokio::test]
  async fn test_handle_callback_session_expired() {
    let mock_oauth = MockOAuthProvider {
      generate_auth_url_result: Arc::new(Mutex::new(Ok((
        "https://auth.example.com/authorize".to_string(),
        CsrfToken::new("test_state".to_string()),
        PkceCodeVerifier::new("test_verifier".to_string()),
      )))),
      received_scopes: Arc::new(Mutex::new(None)),
      get_token_result: Arc::new(Mutex::new(Ok(OAuthTokenResponse {
        access_token: "test_access_token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some("test_refresh_token".to_string()),
        scope: "openid profile".to_string(),
      }))),
      provider_config: Arc::new(Mutex::new(Ok(ProviderConfig {
        authorization_endpoint: "https://auth.example.com/authorize".to_string(),
        token_endpoint: "https://auth.example.com/token".to_string(),
        revocation_endpoint: Some("https://auth.example.com/revoke".to_string()),
        client_id: "test_client_id".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        issuer: "https://auth.example.com".to_string(),
      }))),
    };

    let mock_cache = MockCacheProvider::new();

    let use_case = AuthenticationUseCase::new(mock_oauth, mock_cache);

    set_mock_time(TEST_TIMESTAMP + AuthorizationConstants::PKCE_SESSION_TTL_SECONDS + 1);

    let request = CallbackRequest {
      code: "test_code".to_string(),
      state: "test_state".to_string(),
      code_verifier: "test_verifier".to_string(),
    };

    let result = use_case.handle_callback(request).await;

    reset_mock_time();

    assert!(result.is_err());
    match result.unwrap_err() {
      AuthError::SessionExpired => {}
      err => panic!("Expected SessionExpired but got: {:?}", err),
    }
  }

  #[tokio::test]
  async fn test_handle_callback_token_error() {
    let mock_oauth = MockOAuthProvider {
      generate_auth_url_result: Arc::new(Mutex::new(Ok((
        "https://auth.example.com/authorize".to_string(),
        CsrfToken::new("test_state".to_string()),
        PkceCodeVerifier::new("test_verifier".to_string()),
      )))),
      received_scopes: Arc::new(Mutex::new(None)),
      get_token_result: Arc::new(Mutex::new(Err(AuthError::ProviderError(
        "Failed to get token".to_string(),
      )))),
      provider_config: Arc::new(Mutex::new(Ok(ProviderConfig {
        authorization_endpoint: "https://auth.example.com/authorize".to_string(),
        token_endpoint: "https://auth.example.com/token".to_string(),
        revocation_endpoint: Some("https://auth.example.com/revoke".to_string()),
        client_id: "test_client_id".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        issuer: "https://auth.example.com".to_string(),
      }))),
    };

    let mock_cache = MockCacheProvider::new();
    let use_case = AuthenticationUseCase::new(mock_oauth, mock_cache);

    let request = CallbackRequest {
      code: "test_code".to_string(),
      state: "test_state".to_string(),
      code_verifier: "test_verifier".to_string(),
    };
    set_mock_time(TEST_TIMESTAMP);

    let result = use_case.handle_callback(request).await;

    reset_mock_time();

    assert!(result.is_err());
    match result.unwrap_err() {
      AuthError::ProviderError(msg) => {
        assert_eq!(msg, "Failed to get token");
      }
      err => panic!("Expected ProviderError but got: {:?}", err),
    }
  }
}
