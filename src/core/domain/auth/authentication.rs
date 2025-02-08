use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct AuthenticationSession {
    id: SessionId,
    user_id: UserId,
    expires_at: ExpiresAt,
}

#[derive(Debug, PartialEq)]
pub enum AuthenticationState {
    Unauthenticated,
    PendingAuthentication,
    Authenticated,
    Failed,
}
#[derive(Debug)]
pub struct Authentication {
    id: AuthenticationId,
    user_id: UserId,
    state: AuthenticationState,
    credentials: Credentials,
    session: Option<AuthenticationSession>,
    created_at: SystemTime,
}

impl Authentication {
    pub fn authenticate(&mut self, credentials: Credentials) -> Result<AuthenticationSession, AuthError> {
        if !self.credentials.verify(&credentials) {
            return Err(AuthError::InvalidCredentials);
        }

        let session = AuthenticationSession::new(self.user_id.clone());
        self.session = Some(session.clone());
        self.state = AuthenticationState::Authenticated;
        Ok(session)
    }
    pub fn invalidate_session(&mut self) {
        self.state = None;
        self.state = AuthenticationState::Unauthenticated
    }

}