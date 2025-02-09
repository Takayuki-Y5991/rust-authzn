use crate::core::domain::auth::{
  error::AuthError,
  pkce::{CodeChallenge, CodeVerifier},
  shared::{AuthenticationId, ClientId, ExpiresAt, RedirectUri, Scopes},
};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct AuthorizationCode(String);

impl AuthorizationCode {
  pub fn new(code: String) -> Result<Self, AuthError> {
    if code.is_empty() {
      return Err(AuthError::ValidationError(
        "Authorization code cannot be empty".to_string(),
      ));
    }
    Ok(Self(code))
  }

  pub fn value(&self) -> &str {
    &self.0
  }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthenticationState {
  Initial,
  AuthorizationPending,
  CodeReceived,
  TokenReceived,
  Failed,
  Expired,
}

#[derive(Debug, Clone)]
pub struct State(String);

impl State {
  pub fn new() -> Self {
    Self(uuid::Uuid::now_v7().to_string())
  }

  pub fn verify(&self, state: &str) -> bool {
    self.0 == state
  }

  pub fn value(&self) -> &str {
    &self.0
  }
}
impl Default for State {
  fn default() -> Self {
    Self::new()
  }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthenticationSession {
  auth_id: AuthenticationId,
  client_id: ClientId,
  state: State,
  code_verifier: CodeVerifier,
  code_challenge: CodeChallenge,
  redirect_uri: RedirectUri,
  scopes: Scopes,
  authorization_code: Option<AuthorizationCode>,
  expires_at: ExpiresAt,
  created_at: SystemTime,
}

impl AuthenticationSession {
  pub fn new(
    client_id: ClientId,
    redirect_uri: RedirectUri,
    scopes: Scopes,
    code_verifier: CodeVerifier,
    code_challenge: CodeChallenge,
    expires_in: Option<Duration>,
  ) -> Self {
    Self {
      auth_id: AuthenticationId::new(),
      client_id,
      state: State::new(),
      code_verifier,
      code_challenge,
      redirect_uri,
      scopes,
      authorization_code: None,
      expires_at: ExpiresAt::new(expires_in.unwrap_or(Duration::from_secs(600))),
      created_at: SystemTime::now(),
    }
  }

  pub fn set_authorization_code(&mut self, code: String) -> Result<(), AuthError> {
    self.authorization_code = Some(AuthorizationCode::new(code)?);
    Ok(())
  }

  pub fn is_valid(&self) -> bool {
    !self.expires_at.is_expired()
  }

  pub fn auth_id(&self) -> &AuthenticationId {
    &self.auth_id
  }

  pub fn verify_state(&self, state: &str) -> bool {
    self.state.verify(state)
  }

  pub fn state_value(&self) -> &str {
    self.state.value()
  }

  pub fn code_verifier(&self) -> &CodeVerifier {
    &self.code_verifier
  }

  pub fn code_challenge(&self) -> &CodeChallenge {
    &self.code_challenge
  }

  pub fn redirect_uri(&self) -> &RedirectUri {
    &self.redirect_uri
  }

  pub fn scopes(&self) -> &Scopes {
    &self.scopes
  }

  pub fn authorization_code(&self) -> Option<&AuthorizationCode> {
    self.authorization_code.as_ref()
  }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Authentication {
  id: AuthenticationId,
  state: AuthenticationState,
  session: Option<AuthenticationSession>,
  created_at: SystemTime,
}

impl Authentication {
  pub fn new() -> Self {
    Self {
      id: AuthenticationId::new(),
      state: AuthenticationState::Initial,
      session: None,
      created_at: SystemTime::now(),
    }
  }

  pub fn start_authorization(
    &mut self,
    client_id: ClientId,
    redirect_uri: RedirectUri,
    scopes: Scopes,
  ) -> Result<&AuthenticationSession, AuthError> {
    if self.state != AuthenticationState::Initial {
      return Err(AuthError::InvalidState);
    }

    let code_verifier = CodeVerifier::generate();
    let code_challenge = CodeChallenge::from_verifier(&code_verifier);

    let session = AuthenticationSession::new(client_id, redirect_uri, scopes, code_verifier, code_challenge, None);

    self.session = Some(session);
    self.state = AuthenticationState::AuthorizationPending;

    Ok(self.session.as_ref().unwrap())
  }

  pub fn handle_authorization_code(
    &mut self,
    code: String,
    state: String,
  ) -> Result<&AuthenticationSession, AuthError> {
    if self.state != AuthenticationState::AuthorizationPending {
      return Err(AuthError::InvalidState);
    }

    let session = self.session.as_mut().ok_or(AuthError::InvalidState)?;

    if !session.is_valid() {
      self.state = AuthenticationState::Expired;
      return Err(AuthError::SessionExpired);
    }

    if !session.verify_state(&state) {
      self.state = AuthenticationState::Failed;
      return Err(AuthError::InvalidState);
    }

    session.set_authorization_code(code)?;
    self.state = AuthenticationState::CodeReceived;
    Ok(session)
  }

  pub fn handle_token_received(&mut self) -> Result<(), AuthError> {
    match self.state {
      AuthenticationState::CodeReceived => {
        let session = self.session.as_ref().ok_or(AuthError::InvalidState)?;
        if !session.is_valid() {
          self.state = AuthenticationState::Expired;
          return Err(AuthError::SessionExpired);
        }
        self.state = AuthenticationState::TokenReceived;
        Ok(())
      }
      _ => Err(AuthError::InvalidState),
    }
  }

  pub fn id(&self) -> &AuthenticationId {
    &self.id
  }

  pub fn state(&self) -> &AuthenticationState {
    &self.state
  }

  pub fn session(&self) -> Option<&AuthenticationSession> {
    self.session.as_ref()
  }
}
impl Default for Authentication {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn setup_test_data() -> (ClientId, RedirectUri, Scopes) {
    (
      ClientId::new("test_client".to_string()).unwrap(),
      RedirectUri::new("http://localhost:8080/callback".to_string()).unwrap(),
      Scopes::new(vec!["read".to_string(), "write".to_string()]).unwrap(),
    )
  }
  #[test]
  fn test_authorization_flow() -> Result<(), AuthError> {
    let mut auth = Authentication::new();
    let (client_id, redirect_uri, scopes) = setup_test_data();

    // Start authorization
    let state = {
      let session = auth.start_authorization(client_id, redirect_uri, scopes)?;
      session.state_value().to_string()
    }; // sessionの参照はここでドロップ
    assert_eq!(auth.state(), &AuthenticationState::AuthorizationPending);

    // Handle authorization code
    auth.handle_authorization_code("test_code".to_string(), state)?;
    assert_eq!(auth.state(), &AuthenticationState::CodeReceived);

    // Handle token received
    auth.handle_token_received()?;
    assert_eq!(auth.state(), &AuthenticationState::TokenReceived);

    Ok(())
  }
  #[test]
  fn test_session_expiration() -> Result<(), AuthError> {
    use std::thread::sleep;

    // まずCodeVerifierを生成
    let code_verifier = CodeVerifier::generate();
    let code_challenge = CodeChallenge::from_verifier(&code_verifier);

    // そしてセッションを作成
    let session = AuthenticationSession::new(
      ClientId::new("test_client".to_string())?,
      RedirectUri::new("http://localhost:8080/callback".to_string())?,
      Scopes::new(vec!["read".to_string(), "write".to_string()])?,
      code_verifier,
      code_challenge,
      Some(Duration::from_nanos(1)), // 短い有効期限を設定
    );

    // 有効期限切れを待つ
    sleep(Duration::from_millis(1));

    // セッションの有効性を確認
    assert!(!session.is_valid());

    Ok(())
  }
}
