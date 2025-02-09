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

pub struct OkkaOAuthProvider {
  client: OriginalClient<
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
  >,
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
      token_type: String::from(token_result.token_type().as_ref()),
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
      token_type: String::from(token_result.token_type().as_ref()),
      expires_in: token_result.expires_in().map(|d| d.as_secs()).unwrap_or(3600),
      refresh_token: token_result.refresh_token().map(|t| t.secret().to_string()),
      scope: token_result
        .scopes()
        .map(|s| s.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" "))
        .unwrap_or_default(),
    })
  }

  async fn revoke_token(&self, token: String) -> Result<(), AuthError> {
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
