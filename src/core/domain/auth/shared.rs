use crate::core::domain::auth::error::AuthError;
use std::time::{Duration, SystemTime};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticationId(Uuid);
impl AuthenticationId {
  pub fn new() -> Self {
    Self(Uuid::now_v7())
  }
  pub fn value(&self) -> &Uuid {
    &self.0
  }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationId(Uuid);
impl AuthorizationId {
  pub fn new() -> Self {
    Self(Uuid::now_v7())
  }
  pub fn value(&self) -> &Uuid {
    &self.0
  }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionId(Uuid);
impl SessionId {
  pub fn new() -> Self {
    Self(Uuid::now_v7())
  }
  pub fn value(&self) -> &Uuid {
    &self.0
  }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserId(String);
impl UserId {
  pub fn new(value: String) -> Result<Self, AuthError> {
    if value.is_empty() {
      return Err(AuthError::ValidationError("UserId cannot be empty".to_string()));
    }
    if value.len() > 255 {
      return Err(AuthError::ValidationError("UserId is too long".to_string()));
    }
    if !value.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
      return Err(AuthError::ValidationError(
        "UserId contains invalid characters".to_string(),
      ));
    }
    Ok(Self(value))
  }

  pub fn value(&self) -> &str {
    &self.0
  }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientId(String);
impl ClientId {
  pub fn new(value: String) -> Result<Self, AuthError> {
    if value.is_empty() {
      return Err(AuthError::ValidationError("ClientId cannot be empty".to_string()));
    }
    if value.len() > 255 {
      return Err(AuthError::ValidationError("ClientId is too long".to_string()));
    }
    if !value.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
      return Err(AuthError::ValidationError(
        "ClientId contains invalid characters".to_string(),
      ));
    }
    Ok(Self(value))
  }

  pub fn value(&self) -> &str {
    &self.0
  }
}

#[derive(Debug, Clone)]
pub struct ExpiresAt(SystemTime);
impl ExpiresAt {
  pub fn new(duration: Duration) -> Self {
    Self(SystemTime::now() + duration)
  }

  pub fn from_system_time(time: SystemTime) -> Self {
    Self(time)
  }

  pub fn is_expired(&self) -> bool {
    SystemTime::now() > self.0
  }

  pub fn value(&self) -> SystemTime {
    self.0
  }

  pub fn remaining_time(&self) -> Option<Duration> {
    self.0.duration_since(SystemTime::now()).ok()
  }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Scopes(Vec<String>);

impl Scopes {
  pub fn new(scopes: Vec<String>) -> Result<Self, AuthError> {
    if scopes.is_empty() {
      return Err(AuthError::ValidationError("Scopes cannot be empty".to_string()));
    }
    for scope in &scopes {
      if scope.is_empty() {
        return Err(AuthError::ValidationError("Scope cannot be empty".to_string()));
      }
      if !scope.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') {
        return Err(AuthError::ValidationError("Invalid scope format".to_string()));
      }
    }
    Ok(Self(scopes))
  }

  pub fn contains_all(&self, other: &Scopes) -> bool {
    other.0.iter().all(|scope| self.0.contains(scope))
  }

  pub fn as_vec(&self) -> &Vec<String> {
    &self.0
  }
  pub fn as_space_separated_string(&self) -> String {
    self.0.join(" ")
  }

  pub fn intersect(&self, other: &Scopes) -> Self {
    let intersection: Vec<String> = self.0.iter().filter(|s| other.0.contains(s)).cloned().collect();
    Self(intersection)
  }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RedirectUri(Url);
impl RedirectUri {
  pub fn new(value: String) -> Result<Self, AuthError> {
    let url = Url::parse(&value).map_err(|_| AuthError::ValidationError("Invalid URL format".to_string()))?;

    if url.scheme() != "https" && url.scheme() != "http" {
      return Err(AuthError::ValidationError(
        "URL must use HTTPS or HTTP scheme".to_string(),
      ));
    }

    if url.host_str().is_none() {
      return Err(AuthError::ValidationError("URL must have a host".to_string()));
    }

    Ok(Self(url))
  }

  pub fn value(&self) -> &str {
    self.0.as_str()
  }

  pub fn is_https(&self) -> bool {
    self.0.scheme() == "https"
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_redirect_uri_validation() {
    // 有効なURLのテスト
    assert!(RedirectUri::new("https://example.com/callback".to_string()).is_ok());
    assert!(RedirectUri::new("http://localhost:3000/callback".to_string()).is_ok());

    assert!(RedirectUri::new("ftp://example.com".to_string()).is_err());
    assert!(RedirectUri::new("invalid-url".to_string()).is_err());
  }

  #[test]
  fn test_scopes_validation() {
    let valid_scopes = vec!["read".to_string(), "write".to_string()];
    assert!(Scopes::new(valid_scopes).is_ok());

    let invalid_scopes = vec!["read space".to_string()];
    assert!(Scopes::new(invalid_scopes).is_err());
  }
}
