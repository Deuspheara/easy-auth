//! The core port delegates to feature-owned transactions; no policy lives here.
use crate::{Postgres, unavailable};
use async_trait::async_trait;
use auth_core::{Repository, Result, SecurityNotice, SessionPage, User, Verifier};
use uuid::Uuid;

#[async_trait]
impl Repository for Postgres {
    async fn begin_email_attachment(
        &self,
        realm: Uuid,
        current: Verifier,
        email: &str,
        token: Verifier,
        browser: Verifier,
    ) -> Result<()> {
        Postgres::begin_email_attachment(self, realm, current, email, token, browser).await
    }
    async fn finish_email_attachment(
        &self,
        realm: Uuid,
        current: Verifier,
        token: Verifier,
        browser: Verifier,
        replacement: Verifier,
    ) -> Result<()> {
        Postgres::finish_email_attachment(self, realm, current, token, browser, replacement).await
    }
    async fn begin_email(
        &self,
        realm: Uuid,
        email: &str,
        token: Verifier,
        browser: Verifier,
        source: Verifier,
    ) -> Result<()> {
        Postgres::begin_email(self, realm, email, token, browser, source).await
    }
    async fn finish_email(
        &self,
        realm: Uuid,
        token: Verifier,
        browser: Verifier,
        session: Verifier,
    ) -> Result<User> {
        Postgres::finish_email(self, realm, token, browser, session).await
    }
    async fn authenticate(&self, realm: Uuid, session: Verifier) -> Result<User> {
        Postgres::authenticate(self, realm, session).await
    }
    async fn revoke(&self, realm: Uuid, session: Verifier) -> Result<()> {
        Postgres::revoke(self, realm, session).await
    }
    async fn list_sessions(
        &self,
        realm: Uuid,
        current: Verifier,
        after: Option<Uuid>,
    ) -> Result<SessionPage> {
        Postgres::list_sessions(self, realm, current, after).await
    }
    async fn revoke_session(&self, realm: Uuid, current: Verifier, target: Uuid) -> Result<bool> {
        Postgres::revoke_session(self, realm, current, target).await
    }
    async fn revoke_all_sessions(&self, realm: Uuid, current: Verifier) -> Result<()> {
        Postgres::revoke_all_sessions(self, realm, current).await
    }
    async fn admit_password(&self, realm: Uuid, email: &str, source: Verifier) -> Result<()> {
        Postgres::admit_password(self, realm, email, source).await
    }
    async fn admit_user_action(&self, realm: Uuid, user: Uuid, source: Verifier) -> Result<()> {
        Postgres::admit_user_action(self, realm, user, source).await
    }
    async fn password_hash(&self, realm: Uuid, email: &str) -> Result<Option<String>> {
        Postgres::password_hash(self, realm, email).await
    }
    async fn enroll_password(
        &self,
        realm: Uuid,
        current: Verifier,
        hash: &str,
        replacement: Verifier,
    ) -> Result<()> {
        Postgres::enroll_password(self, realm, current, hash, replacement).await
    }
    async fn password_login(
        &self,
        realm: Uuid,
        email: &str,
        hash: &str,
        session: Verifier,
    ) -> Result<()> {
        Postgres::password_login(self, realm, email, hash, session).await
    }
    async fn begin_password_reset(
        &self,
        realm: Uuid,
        email: &str,
        token: Verifier,
        browser: Verifier,
    ) -> Result<()> {
        Postgres::begin_password_reset(self, realm, email, token, browser).await
    }
    async fn password_reset_email(
        &self,
        realm: Uuid,
        token: Verifier,
        browser: Verifier,
    ) -> Result<String> {
        Postgres::password_reset_email(self, realm, token, browser).await
    }
    async fn finish_password_reset(
        &self,
        realm: Uuid,
        token: Verifier,
        browser: Verifier,
        hash: &str,
    ) -> Result<()> {
        Postgres::finish_password_reset(self, realm, token, browser, hash).await
    }
    async fn claim_security_notice(&self, realm: Uuid) -> Result<Option<SecurityNotice>> {
        Postgres::claim_security_notice(self, realm).await
    }
    async fn complete_security_notice(
        &self,
        realm: Uuid,
        id: Uuid,
        lease: Uuid,
        delivered: bool,
    ) -> Result<()> {
        Postgres::complete_security_notice(self, realm, id, lease, delivered).await
    }
    async fn begin_email_change(
        &self,
        realm: Uuid,
        current: Verifier,
        email: &str,
        old: Verifier,
        new: Verifier,
        browser: Verifier,
    ) -> Result<String> {
        Postgres::begin_email_change(self, realm, current, email, old, new, browser).await
    }
    async fn confirm_email_change(
        &self,
        realm: Uuid,
        current: Verifier,
        token: Verifier,
        browser: Verifier,
    ) -> Result<bool> {
        Postgres::confirm_email_change(self, realm, current, token, browser).await
    }
    async fn begin_account_deletion(
        &self,
        realm: Uuid,
        current: Verifier,
        token: Verifier,
        browser: Verifier,
    ) -> Result<String> {
        Postgres::begin_account_deletion(self, realm, current, token, browser).await
    }
    async fn finish_account_deletion(
        &self,
        realm: Uuid,
        current: Verifier,
        token: Verifier,
        browser: Verifier,
    ) -> Result<()> {
        Postgres::finish_account_deletion(self, realm, current, token, browser).await
    }
    async fn ready(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(unavailable)?;
        Ok(())
    }
}
