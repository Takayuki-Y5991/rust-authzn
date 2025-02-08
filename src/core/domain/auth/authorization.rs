
#[derive(Debug)]
pub struct Authorization {
    id: AuthorizationId,
    client_id: ClientId,
    user_id: UserId,
    scopes: Scopes,
    state: AuthorizationState,
    code_challenge: Option<CodeChallenge>,
    authorization_code: Option<AuthorizationCode>,
}

impl Authorization {
    pub fn authorize(&mut self, requested_scopes: Scopes) -> Result<AuthorizationCode, AuthError> {
        if !self.scopes.contains_all(&requested_scopes) {
            return Err(AuthError::InsufficientScopes);
        }

        if self.state != AuthorizationState::Pending {
            return Err(AuthError::InvalidState);
        }

        let code = AuthorizationCode::generate(
            self.client_id.clone(),
            self.user_id.clone(),
            requested_scopes,
        );

        self.authorization_code = Some(code.clone());
        self.state = AuthorizationState::Authorized;

        Ok(code)
    }

    pub fn exchange_code(
        &mut self,
        code: AuthorizationCode,
        code_verifier: &CodeVerifier,
    ) -> Result<AccessToken, AuthError> {
        if self.state != AuthorizationState::Authorized {
            return Err(AuthError::InvalidState);
        }

        if !code.verify(code_verifier) {
            return Err(AuthError::InvalidCodeVerifier);
        }

        let token = AccessToken::new(
            self.client_id.clone(),
            self.user_id.clone(),
            self.scopes.clone(),
        );

        self.state = AuthorizationState::Completed;
        Ok(token)
    }
}