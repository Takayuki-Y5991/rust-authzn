use crate::core::domain::auth::{authentication::AuthenticationSession, error::AuthError, shared::AuthenticationId};
use async_trait::async_trait;

#[async_trait]
pub trait AuthenticationRepository {
  async fn save_session(&self, session: &AuthenticationSession) -> Result<(), AuthError>;

  async fn find_session(&self, id: &AuthenticationId) -> Result<Option<AuthenticationSession>, AuthError>;
}
