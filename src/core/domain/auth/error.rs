#[derive(thiserror::Error, Debug)]
pub enum AuthError {
  #[error("Invalid credentials")]
  InvalidCredentials,

  #[error("Invalid state for request operation")]
  InvalidState,

  #[error("Insufficient scopes")]
  InsufficientScopes,

  #[error("Invalid code verifier")]
  InvalidCodeVerifier,

  #[error("Session expired")]
  SessionExpired,

  #[error("Configuration error: {0}")]
  ConfigurationError(String),

  #[error("Validation error: {0}")]
  ValidationError(String),
}
