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

  pub fn from_system_time(seconds: u64) -> Self {
    Self::new(Duration::from_secs(seconds))
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

  pub fn contains(&self, scope: &str) -> bool {
    self.0.contains(&scope.to_string())
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
  fn test_id_generation() {
    let auth_id1 = AuthenticationId::new();
    let auth_id2 = AuthenticationId::new();
    assert_ne!(auth_id1, auth_id2, "Generated IDs should be unique");

    let session_id1 = SessionId::new();
    let session_id2 = SessionId::new();
    assert_ne!(session_id1, session_id2, "Generated session IDs should be unique");
  }

  #[test]
  fn test_user_id_validation() {
    // 有効なケース
    assert!(UserId::new("user123".to_string()).is_ok());
    assert!(UserId::new("user_123-test".to_string()).is_ok());

    // 無効なケース
    assert!(UserId::new("".to_string()).is_err());
    assert!(UserId::new("a".repeat(256)).is_err());
    assert!(UserId::new("user@123".to_string()).is_err());
    assert!(UserId::new("user 123".to_string()).is_err());
  }

  #[test]
  fn test_redirect_uri_validation() {
    // 有効なURLのテスト
    assert!(RedirectUri::new("https://example.com/callback".to_string()).is_ok());
    assert!(RedirectUri::new("http://localhost:3000/callback".to_string()).is_ok());
    assert!(RedirectUri::new("https://sub.example.com/callback?param=value".to_string()).is_ok());

    // 無効なURLのテスト
    assert!(RedirectUri::new("ftp://example.com".to_string()).is_err());
    assert!(RedirectUri::new("invalid-url".to_string()).is_err());
    assert!(RedirectUri::new("".to_string()).is_err());
    assert!(RedirectUri::new("https://".to_string()).is_err());
  }

  #[test]
  fn test_scopes() {
    // 基本的な検証
    let valid_scopes = vec!["read".to_string(), "write".to_string()];
    let scopes = Scopes::new(valid_scopes.clone()).unwrap();
    assert_eq!(scopes.as_vec(), &valid_scopes);

    // 空のスコープ
    assert!(Scopes::new(vec![]).is_err());
    assert!(Scopes::new(vec!["".to_string()]).is_err());

    // contains_allのテスト
    let full_scopes = Scopes::new(vec!["read".to_string(), "write".to_string(), "delete".to_string()]).unwrap();
    let partial_scopes = Scopes::new(vec!["read".to_string(), "write".to_string()]).unwrap();
    assert!(full_scopes.contains_all(&partial_scopes));
    assert!(!partial_scopes.contains_all(&full_scopes));

    // intersectのテスト
    let scopes1 = Scopes::new(vec!["read".to_string(), "write".to_string()]).unwrap();
    let scopes2 = Scopes::new(vec!["write".to_string(), "delete".to_string()]).unwrap();
    let intersection = scopes1.intersect(&scopes2);
    assert_eq!(intersection.as_vec(), &vec!["write".to_string()]);

    // as_space_separated_stringのテスト
    let scopes = Scopes::new(vec!["read".to_string(), "write".to_string()]).unwrap();
    assert_eq!(scopes.as_space_separated_string(), "read write");
  }
}
