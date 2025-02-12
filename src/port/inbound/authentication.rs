use crate::core::domain::auth::error::AuthError;
use async_trait::async_trait;

#[async_trait]
pub trait AuthenticationPort {
  async fn initialize_authentication(
    &self,
    request: AuthenticationRequest,
  ) -> Result<AuthenticationResponse, AuthError>;

  async fn handle_callback(&self, code: String, state: String) -> Result<CallbackResponse, AuthError>;
}

pub struct AuthenticationRequest {
  pub client_id: String,
  pub redirect_uri: String,
  pub scope: String,
  pub state: Option<String>,
}

pub struct AuthenticationResponse {
  pub authorization_url: String,
  pub state: String,
}

pub struct CallbackResponse {
  pub code: String,
  pub session_state: String,
}
