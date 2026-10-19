use crate::{Result, Secret, SecurityNotice, SessionPage, User, Verifier};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait Repository: Send + Sync {
    /// Rate admission and challenge persistence must be atomic. Clock is database-owned.
    async fn begin_email(
        &self,
        realm: Uuid,
        email: &str,
        token: Verifier,
        browser: Verifier,
        source: Verifier,
    ) -> Result<()>;
    /// Consume proof, create/resolve verified identity, issue session and safe audit in one transaction.
    async fn finish_email(
        &self,
        realm: Uuid,
        token: Verifier,
        browser: Verifier,
        session: Verifier,
    ) -> Result<User>;
    async fn authenticate(&self, realm: Uuid, session: Verifier) -> Result<User>;
    async fn revoke(&self, realm: Uuid, session: Verifier) -> Result<()>;
    /// Validate/touch the caller, then list at most one bounded page of its active sessions.
    async fn list_sessions(
        &self,
        realm: Uuid,
        current: Verifier,
        after: Option<Uuid>,
    ) -> Result<SessionPage>;
    /// Revalidate fresh authentication under user/session locks. True means caller was revoked.
    async fn revoke_session(&self, realm: Uuid, current: Verifier, target: Uuid) -> Result<bool>;
    /// Revoke all sessions and outstanding proofs atomically, including the initiating session.
    async fn revoke_all_sessions(&self, realm: Uuid, current: Verifier) -> Result<()>;
    async fn admit_password(&self, realm: Uuid, email: &str, source: Verifier) -> Result<()>;
    /// User/source budgets for authenticated operations without a mailbox identity.
    async fn admit_user_action(&self, realm: Uuid, user: Uuid, source: Verifier) -> Result<()>;
    async fn password_hash(&self, realm: Uuid, email: &str) -> Result<Option<String>>;
    /// Validate fresh session, insert credential once, revoke previous sessions and issue replacement atomically.
    async fn enroll_password(
        &self,
        realm: Uuid,
        current: Verifier,
        hash: &str,
        replacement: Verifier,
    ) -> Result<()>;
    /// Recheck the exact credential verified outside the transaction before issuing a session.
    async fn password_login(
        &self,
        realm: Uuid,
        email: &str,
        hash: &str,
        session: Verifier,
    ) -> Result<()>;
    async fn begin_password_reset(
        &self,
        realm: Uuid,
        email: &str,
        token: Verifier,
        browser: Verifier,
    ) -> Result<()>;
    async fn password_reset_email(
        &self,
        realm: Uuid,
        token: Verifier,
        browser: Verifier,
    ) -> Result<String>;
    async fn finish_password_reset(
        &self,
        realm: Uuid,
        token: Verifier,
        browser: Verifier,
        hash: &str,
    ) -> Result<()>;
    async fn claim_security_notice(&self, realm: Uuid) -> Result<Option<SecurityNotice>>;
    async fn complete_security_notice(
        &self,
        realm: Uuid,
        id: Uuid,
        lease: Uuid,
        delivered: bool,
    ) -> Result<()>;
    async fn begin_email_change(
        &self,
        realm: Uuid,
        current: Verifier,
        email: &str,
        old: Verifier,
        new: Verifier,
        browser: Verifier,
    ) -> Result<String>;
    async fn confirm_email_change(
        &self,
        realm: Uuid,
        current: Verifier,
        token: Verifier,
        browser: Verifier,
    ) -> Result<bool>;
    async fn begin_account_deletion(
        &self,
        realm: Uuid,
        current: Verifier,
        token: Verifier,
        browser: Verifier,
    ) -> Result<String>;
    async fn finish_account_deletion(
        &self,
        realm: Uuid,
        current: Verifier,
        token: Verifier,
        browser: Verifier,
    ) -> Result<()>;
    async fn ready(&self) -> Result<()>;
}
#[async_trait]
pub trait EmailDelivery: Send + Sync {
    async fn sign_in(&self, email: &str, token: &Secret) -> Result<()>;
    async fn password_reset(&self, email: &str, token: &Secret) -> Result<()>;
    async fn password_changed(&self, email: &str) -> Result<()>;
    async fn email_change(&self, email: &str, token: &Secret) -> Result<()>;
    async fn account_deletion(&self, email: &str, token: &Secret) -> Result<()>;
    async fn email_changed(&self, email: &str) -> Result<()>;
    async fn account_deleted(&self, email: &str) -> Result<()>;
}
