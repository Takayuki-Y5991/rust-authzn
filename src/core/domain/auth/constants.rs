pub struct AuthorizationConstants;

impl AuthorizationConstants {
  pub const PKCE_SESSION_TTL_SECONDS: u64 = 600;
  pub const PKCE_SESSION_KEY_PREFIX: &'static str = "auth:pkce:";

  pub const REFRESH_TOKEN_TTL_DAYS: u64 = 30;

  pub const ACCESS_TOKEN_TTL_MINUTES: u64 = 60;

  pub fn pkce_session_key(state: &str) -> String {
    format!("{}:{}", Self::PKCE_SESSION_KEY_PREFIX, state)
  }
}
