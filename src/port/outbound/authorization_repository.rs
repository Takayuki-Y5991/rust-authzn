use crate::core::domain::auth::{authorization::Authorization, error::AuthError, shared::AuthorizationId};
use async_trait::async_trait;

#[async_trait]
pub trait AuthorizationRepository {
  async fn save_authorization(&self, authorization: &Authorization) -> Result<(), AuthError>;

  async fn find_authorization(&self, id: &AuthorizationId) -> Result<Option<Authorization>, AuthError>;
}
