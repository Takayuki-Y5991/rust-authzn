use async_trait::async_trait;
use oauth2::{
  basic::{BasicClient, BasicErrorResponseType, BasicTokenType},
  reqwest::{self, Client},
  AuthUrl, AuthorizationCode, Client as OriginalClient, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
  EndpointNotSet, EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken,
  RevocationErrorResponseType, Scope, StandardErrorResponse, StandardRevocableToken,
  StandardTokenIntrospectionResponse, StandardTokenResponse, TokenResponse as OAuth2TokenResponse, TokenUrl,
};

use crate::{
  core::domain::auth::error::AuthError,
  port::outbound::oauth_provider::{OAuthProvider, ProviderConfig, RefreshTokenRequest, TokenRequest, TokenResponse},
};

type OAuthClient = OriginalClient<
  StandardErrorResponse<BasicErrorResponseType>,
  StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
  StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
  StandardRevocableToken,
  StandardErrorResponse<RevocationErrorResponseType>,
  EndpointSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointSet,
>;

pub struct OkkaOAuthProvider {
  client: OAuthClient,
  http_client: Client,
}

impl OkkaOAuthProvider {
  pub fn new(
    auth_url: String,
    token_url: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_url: String,
  ) -> Result<Self, AuthError> {
    let client = BasicClient::new(ClientId::new(client_id))
      .set_redirect_uri(RedirectUrl::new(redirect_url).map_err(|e| AuthError::ConfigurationError(e.to_string()))?)
      .set_auth_uri(AuthUrl::new(auth_url).map_err(|e| AuthError::ConfigurationError(e.to_string()))?)
      .set_token_uri(TokenUrl::new(token_url).map_err(|e| AuthError::ConfigurationError(e.to_string()))?);

    let client = if let Some(secret) = client_secret {
      client.set_client_secret(ClientSecret::new(secret))
    } else {
      client
    };

    let http_client = reqwest::Client::builder()
      .redirect(reqwest::redirect::Policy::none())
      .build()
      .map_err(|e| AuthError::ConfigurationError(e.to_string()))?;

    Ok(Self { client, http_client })
  }
  pub fn generate_auth_url(&self, scopes: Vec<String>) -> Result<(String, CsrfToken, PkceCodeVerifier), AuthError> {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut auth_url_builder = self.client.authorize_url(CsrfToken::new_random);

    // Add scopes
    for scope in scopes {
      auth_url_builder = auth_url_builder.add_scope(Scope::new(scope));
    }

    let (auth_url, csrf_token) = auth_url_builder.set_pkce_challenge(pkce_challenge).url();

    Ok((auth_url.to_string(), csrf_token, pkce_verifier))
  }
}

#[async_trait]
impl OAuthProvider for OkkaOAuthProvider {
  async fn get_token(&self, request: TokenRequest) -> Result<TokenResponse, AuthError> {
    let token_result = self
      .client
      .exchange_code(AuthorizationCode::new(request.code))
      .set_pkce_verifier(PkceCodeVerifier::new(request.code_verifier))
      .request_async(&self.http_client)
      .await
      .map_err(|e| AuthError::ProviderError(e.to_string()))?;

    Ok(TokenResponse {
      access_token: token_result.access_token().secret().clone(),
      token_type: token_result.token_type().as_ref().to_owned(),
      expires_in: token_result.expires_in().map(|d| d.as_secs()).unwrap_or(3600),
      refresh_token: token_result.refresh_token().map(|t| t.secret().clone()),
      scope: token_result
        .scopes()
        .map(|s| s.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" "))
        .unwrap_or_default(),
    })
  }

  async fn refresh_token(&self, request: RefreshTokenRequest) -> Result<TokenResponse, AuthError> {
    let token_result = self
      .client
      .exchange_refresh_token(&RefreshToken::new(request.refresh_token))
      .request_async(&self.http_client)
      .await
      .map_err(|e| AuthError::ProviderError(e.to_string()))?;

    Ok(TokenResponse {
      access_token: token_result.access_token().secret().clone(),
      token_type: token_result.token_type().as_ref().to_owned(),
      expires_in: token_result.expires_in().map(|d| d.as_secs()).unwrap_or(3600),
      refresh_token: token_result.refresh_token().map(|t| t.secret().to_string()),
      scope: token_result
        .scopes()
        .map(|s| s.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" "))
        .unwrap_or_default(),
    })
  }

  async fn revoke_token(&self, _token: String) -> Result<(), AuthError> {
    // OAuth2 5.xではトークンの失効はオプショナルな機能です
    // プロバイダーが対応していない場合は、NotImplementedエラーを返すなどの対応が必要です
    Err(AuthError::NotImplemented("Token revocation not supported".to_string()))
  }

  async fn get_provider_config(&self) -> Result<ProviderConfig, AuthError> {
    Ok(ProviderConfig {
      authorization_endpoint: self.client.auth_uri().as_str().to_string(),
      token_endpoint: self.client.token_uri().as_str().to_string(),
      revocation_endpoint: None,
    })
  }
}

#[cfg(test)]
mod tests {
  use crate::port::outbound::oauth_provider::GrantType;

  use super::*;
  use serde_json::json;
  use tokio;
  use wiremock::matchers::{method, path};
  use wiremock::{Mock, MockServer, ResponseTemplate};

  const TEST_AUTH_URL: &str = "https://example.com/auth";
  const TEST_TOKEN_URL: &str = "https://example.com/token";
  const TEST_CLIENT_ID: &str = "test_client_id";
  const TEST_CLIENT_SECRET: &str = "test_client_secret";
  const TEST_REDIRECT_URL: &str = "https://example.com/callback";

  #[test]
  fn test_new_provider_with_secret() {
    let provider = OkkaOAuthProvider::new(
      TEST_AUTH_URL.to_string(),
      TEST_TOKEN_URL.to_string(),
      TEST_CLIENT_ID.to_string(),
      Some(TEST_CLIENT_SECRET.to_string()),
      TEST_REDIRECT_URL.to_string(),
    );

    assert!(provider.is_ok());
  }

  #[test]
  fn test_new_provider_without_secret() {
    let provider = OkkaOAuthProvider::new(
      TEST_AUTH_URL.to_string(),
      TEST_TOKEN_URL.to_string(),
      TEST_CLIENT_ID.to_string(),
      None,
      TEST_REDIRECT_URL.to_string(),
    );

    assert!(provider.is_ok());
  }

  #[test]
  fn test_generate_auth_url() {
    let provider = OkkaOAuthProvider::new(
      TEST_AUTH_URL.to_string(),
      TEST_TOKEN_URL.to_string(),
      TEST_CLIENT_ID.to_string(),
      Some(TEST_CLIENT_SECRET.to_string()),
      TEST_REDIRECT_URL.to_string(),
    )
    .unwrap();

    let scopes = vec!["read".to_string(), "write".to_string()];
    let result = provider.generate_auth_url(scopes);

    assert!(result.is_ok());
    let (auth_url, csrf_token, pkce_verifier) = result.unwrap();

    // URLエンコードされた形式でリダイレクトURLを確認
    let encoded_redirect_url = urlencoding::encode(TEST_REDIRECT_URL);
    assert!(auth_url.contains(&encoded_redirect_url.to_string()));
    assert!(auth_url.contains(TEST_AUTH_URL));
    assert!(auth_url.contains(TEST_CLIENT_ID));
    assert!(auth_url.contains("scope=read+write"));
    assert!(!csrf_token.secret().is_empty());
    assert!(!pkce_verifier.secret().is_empty());
  }

  #[tokio::test]
  async fn test_get_token() {
    // モックサーバーのセットアップ
    let mock_server = MockServer::start().await;

    // トークンエンドポイントのモック設定
    Mock::given(method("POST"))
      .and(path("/"))
      .respond_with(ResponseTemplate::new(200).set_body_json(json!({
          "access_token": "test_access_token",
          "token_type": "bearer",
          "expires_in": 3600,
          "refresh_token": "test_refresh_token",
          "scope": "read write"
      })))
      .mount(&mock_server)
      .await;

    let provider = OkkaOAuthProvider::new(
      TEST_AUTH_URL.to_string(),
      mock_server.uri(), // モックサーバーのURLを使用
      TEST_CLIENT_ID.to_string(),
      Some(TEST_CLIENT_SECRET.to_string()),
      TEST_REDIRECT_URL.to_string(),
    )
    .unwrap();

    let request = TokenRequest {
      code: "test_auth_code".to_string(),
      code_verifier: "test_code_verifier".to_string(),
      grant_type: GrantType::AuthorizationCode,
      redirect_uri: TEST_REDIRECT_URL.to_string(),
      client_id: TEST_CLIENT_ID.to_string(),
    };

    let result = provider.get_token(request).await;
    assert!(result.is_ok());

    let token_response = result.unwrap();
    assert_eq!(token_response.access_token, "test_access_token");
    assert_eq!(token_response.token_type, "bearer");
    assert_eq!(token_response.expires_in, 3600);
    assert_eq!(token_response.refresh_token, Some("test_refresh_token".to_string()));
    assert_eq!(token_response.scope, "read write");
  }

  #[tokio::test]
  async fn test_refresh_token() {
    // モックサーバーのセットアップ
    let mock_server = MockServer::start().await;

    // トークンエンドポイントのモック設定
    Mock::given(method("POST"))
      .and(path("/"))
      .respond_with(ResponseTemplate::new(200).set_body_json(json!({
          "access_token": "new_access_token",
          "token_type": "Bearer",
          "expires_in": 3600,
          "refresh_token": "new_refresh_token",
          "scope": "read write"
      })))
      .mount(&mock_server)
      .await;

    let provider = OkkaOAuthProvider::new(
      TEST_AUTH_URL.to_string(),
      mock_server.uri(), // モックサーバーのURLを使用
      TEST_CLIENT_ID.to_string(),
      Some(TEST_CLIENT_SECRET.to_string()),
      TEST_REDIRECT_URL.to_string(),
    )
    .unwrap();

    let request = RefreshTokenRequest {
      refresh_token: "test_refresh_token".to_string(),
      grant_type: GrantType::AuthorizationCode,
      client_id: TEST_CLIENT_ID.to_string(),
    };

    let result = provider.refresh_token(request).await;
    assert!(result.is_ok());

    let token_response = result.unwrap();
    assert_eq!(token_response.access_token, "new_access_token");
    assert_eq!(token_response.token_type, "bearer");
    assert_eq!(token_response.expires_in, 3600);
    assert_eq!(token_response.refresh_token, Some("new_refresh_token".to_string()));
    assert_eq!(token_response.scope, "read write");
  }

  #[tokio::test]
  async fn test_revoke_token() {
    let provider = OkkaOAuthProvider::new(
      TEST_AUTH_URL.to_string(),
      TEST_TOKEN_URL.to_string(),
      TEST_CLIENT_ID.to_string(),
      Some(TEST_CLIENT_SECRET.to_string()),
      TEST_REDIRECT_URL.to_string(),
    )
    .unwrap();

    let result = provider.revoke_token("test_token".to_string()).await;
    assert!(matches!(result, Err(AuthError::NotImplemented(_))));
  }

  #[tokio::test]
  async fn test_get_provider_config() {
    let provider = OkkaOAuthProvider::new(
      TEST_AUTH_URL.to_string(),
      TEST_TOKEN_URL.to_string(),
      TEST_CLIENT_ID.to_string(),
      Some(TEST_CLIENT_SECRET.to_string()),
      TEST_REDIRECT_URL.to_string(),
    )
    .unwrap();

    let result = provider.get_provider_config().await;
    assert!(result.is_ok());

    let config = result.unwrap();
    assert_eq!(config.authorization_endpoint, TEST_AUTH_URL);
    assert_eq!(config.token_endpoint, TEST_TOKEN_URL);
    assert!(config.revocation_endpoint.is_none());
  }
}
