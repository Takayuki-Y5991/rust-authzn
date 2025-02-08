use crate::core::domain::auth::{
  error::AuthError,
  shared::{AuthorizationId, ClientId, ExpiresAt, Scopes},
};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq)]
pub enum AuthorizationState {
  Active,
  Expired,
  Revoked,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenType {
  Bearer,
  Mac,
}

impl TokenType {
  pub fn as_str(&self) -> &str {
    match self {
      TokenType::Bearer => "Bearer",
      TokenType::Mac => "MAC",
    }
  }

  pub fn from_str(s: &str) -> Result<Self, AuthError> {
    match s.to_lowercase().as_str() {
      "bearer" => Ok(TokenType::Bearer),
      "mac" => Ok(TokenType::Mac),
      _ => Err(AuthError::ValidationError("Invalid token type".to_string())),
    }
  }
}

#[derive(Debug, Clone)]
pub struct AccessToken {
  value: String,
  token_type: TokenType,
  expires_at: ExpiresAt,
}

impl AccessToken {
  pub fn new(value: String, token_type: TokenType, expires_in: Duration) -> Result<Self, AuthError> {
    if value.is_empty() {
      return Err(AuthError::ValidationError("Token value cannot be empty".to_string()));
    }

    Ok(Self {
      value,
      token_type,
      expires_at: ExpiresAt::new(expires_in),
    })
  }

  pub fn is_valid(&self) -> bool {
    !self.expires_at.is_expired()
  }

  pub fn value(&self) -> &str {
    &self.value
  }

  pub fn token_type(&self) -> &TokenType {
    &self.token_type
  }

  pub fn expires_at(&self) -> &ExpiresAt {
    &self.expires_at
  }
}

#[derive(Debug)]
pub struct Authorization {
  id: AuthorizationId,
  client_id: ClientId,
  access_token: AccessToken,
  refresh_token: Option<String>,
  granted_scopes: Scopes,
  state: AuthorizationState,
  created_at: SystemTime,
  last_used_at: SystemTime,
}

impl Authorization {
  pub fn new(
    client_id: ClientId,
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    granted_scopes: Scopes,
  ) -> Result<Self, AuthError> {
    let token_type = TokenType::from_str(&token_type)?;
    let access_token = AccessToken::new(access_token, token_type, Duration::from_secs(expires_in))?;

    let now = SystemTime::now();
    Ok(Self {
      id: AuthorizationId::new(),
      client_id,
      access_token,
      refresh_token,
      granted_scopes,
      state: AuthorizationState::Active,
      created_at: now,
      last_used_at: now,
    })
  }

  pub fn verify_scope(&self, required_scope: &str) -> bool {
    if !self.is_valid() {
      return false;
    }
    self.granted_scopes.contains(required_scope)
  }

  pub fn is_valid(&self) -> bool {
    match self.state {
      AuthorizationState::Active => self.access_token.is_valid(),
      _ => false,
    }
  }

  pub fn can_refresh(&self) -> bool {
    self.refresh_token.is_some()
      && (self.state == AuthorizationState::Active || self.state == AuthorizationState::Expired)
  }

  pub fn revoke(&mut self) {
    self.state = AuthorizationState::Revoked;
    self.refresh_token = None;
  }

  pub fn update_token(
    &mut self,
    new_token: String,
    token_type: String,
    expires_in: u64,
    new_refresh_token: Option<String>,
  ) -> Result<(), AuthError> {
    if self.state == AuthorizationState::Revoked {
      return Err(AuthError::InvalidState);
    }

    let token_type = TokenType::from_str(&token_type)?;
    self.access_token = AccessToken::new(new_token, token_type, Duration::from_secs(expires_in))?;

    if let Some(refresh_token) = new_refresh_token {
      self.refresh_token = Some(refresh_token);
    }

    self.last_used_at = SystemTime::now();
    self.state = AuthorizationState::Active;
    Ok(())
  }

  pub fn last_used_at(&self) -> SystemTime {
    self.last_used_at
  }

  pub fn created_at(&self) -> SystemTime {
    self.created_at
  }

  // Getters
  pub fn id(&self) -> &AuthorizationId {
    &self.id
  }

  pub fn client_id(&self) -> &ClientId {
    &self.client_id
  }

  pub fn access_token(&self) -> &AccessToken {
    &self.access_token
  }

  pub fn refresh_token(&self) -> Option<&String> {
    self.refresh_token.as_ref()
  }

  pub fn granted_scopes(&self) -> &Scopes {
    &self.granted_scopes
  }

  pub fn state(&self) -> &AuthorizationState {
    &self.state
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn create_test_authorization() -> Authorization {
    Authorization::new(
      ClientId::new("test_client".to_string()).unwrap(),
      "access_token".to_string(),
      "Bearer".to_string(),
      3600,
      Some("refresh_token".to_string()),
      Scopes::new(vec!["read".to_string(), "write".to_string()]).unwrap(),
    )
    .unwrap()
  }

  #[test]
  fn test_authorization_validity() {
    let auth = create_test_authorization();
    assert!(auth.is_valid());
    assert!(auth.verify_scope("read"));
    assert!(auth.verify_scope("write"));
    assert!(!auth.verify_scope("admin"));
  }

  #[test]
  fn test_token_update() -> Result<(), AuthError> {
    let mut auth = create_test_authorization();
    let old_token = auth.access_token().value().to_string();

    auth.update_token(
      "new_token".to_string(),
      "Bearer".to_string(),
      3600,
      Some("new_refresh_token".to_string()),
    )?;

    assert_ne!(auth.access_token().value(), &old_token);
    assert_eq!(auth.state(), &AuthorizationState::Active);
    assert!(auth.is_valid());
    Ok(())
  }

  #[test]
  fn test_revocation() {
    let mut auth = create_test_authorization();
    assert!(auth.is_valid());
    assert!(auth.can_refresh());

    auth.revoke();
    assert!(!auth.is_valid());
    assert!(!auth.can_refresh());
    assert_eq!(auth.state(), &AuthorizationState::Revoked);
  }

  #[test]
  fn test_token_type_validation() {
    assert!(TokenType::from_str("bearer").is_ok());
    assert!(TokenType::from_str("Bearer").is_ok());
    assert!(TokenType::from_str("BEARER").is_ok());
    assert!(TokenType::from_str("invalid").is_err());
  }

  #[test]
  fn test_expired_token() {
    let mut auth = create_test_authorization();
    std::thread::sleep(Duration::from_millis(1));

    // 期限切れのトークンで更新
    auth
      .update_token(
        "new_token".to_string(),
        "Bearer".to_string(),
        0, // 即時期限切れ
        None,
      )
      .unwrap();

    assert!(!auth.is_valid());
    assert!(!auth.verify_scope("read")); // 期限切れの場合、スコープ検証も失敗
  }
}
