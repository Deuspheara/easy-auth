use super::Auth;
use crate::{Result, Secret, SessionPage, User};
use uuid::Uuid;

impl Auth {
    pub async fn authenticate(&self, session: &Secret) -> Result<User> {
        self.repository
            .authenticate(self.realm, session.verifier())
            .await
    }
    pub async fn logout(&self, session: &Secret) -> Result<()> {
        self.repository.revoke(self.realm, session.verifier()).await
    }
    /// Validate the caller and return a bounded UUID-ordered page of owned active sessions.
    pub async fn list_sessions(
        &self,
        current: &Secret,
        after: Option<Uuid>,
    ) -> Result<SessionPage> {
        self.repository
            .list_sessions(self.realm, current.verifier(), after)
            .await
    }
    /// Revoke an owned public session ID; true only when the initiating session was revoked.
    /// Derive source from trusted connection context, as for other sensitive actions.
    pub async fn revoke_session(
        &self,
        current: &Secret,
        target: Uuid,
        source: &str,
    ) -> Result<bool> {
        self.admit_sensitive_action(current, source).await?;
        self.repository
            .revoke_session(self.realm, current.verifier(), target)
            .await
    }
    /// Revoke current sessions and pending proofs atomically. A subsequent genuine login is allowed.
    pub async fn revoke_all_sessions(&self, current: &Secret, source: &str) -> Result<()> {
        self.admit_sensitive_action(current, source).await?;
        self.repository
            .revoke_all_sessions(self.realm, current.verifier())
            .await
    }
}
