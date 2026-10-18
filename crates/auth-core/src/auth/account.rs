use super::Auth;
use crate::{Result, Secret, normalize_email};

impl Auth {
    pub async fn start_email_change(
        &self,
        current: &Secret,
        email: &str,
        source: &str,
    ) -> Result<Secret> {
        self.admit_sensitive_action(current, source).await?;
        let email = normalize_email(email)?;
        let old = Secret::generate()?;
        let new = Secret::generate()?;
        let browser = Secret::generate()?;
        let previous = self
            .repository
            .begin_email_change(
                self.realm,
                current.verifier(),
                &email,
                old.verifier(),
                new.verifier(),
                browser.verifier(),
            )
            .await?;
        self.email.email_change(&previous, &old).await?;
        self.email.email_change(&email, &new).await?;
        Ok(browser)
    }
    pub async fn confirm_email_change(
        &self,
        current: &Secret,
        token: Secret,
        browser: Secret,
        source: &str,
    ) -> Result<bool> {
        self.admit_sensitive_action(current, source).await?;
        self.repository
            .confirm_email_change(
                self.realm,
                current.verifier(),
                token.verifier(),
                browser.verifier(),
            )
            .await
    }
    pub async fn start_account_deletion(&self, current: &Secret, source: &str) -> Result<Secret> {
        self.admit_sensitive_action(current, source).await?;
        let token = Secret::generate()?;
        let browser = Secret::generate()?;
        let email = self
            .repository
            .begin_account_deletion(
                self.realm,
                current.verifier(),
                token.verifier(),
                browser.verifier(),
            )
            .await?;
        self.email.account_deletion(&email, &token).await?;
        Ok(browser)
    }
    pub async fn finish_account_deletion(
        &self,
        current: &Secret,
        token: Secret,
        browser: Secret,
        source: &str,
    ) -> Result<()> {
        self.admit_sensitive_action(current, source).await?;
        self.repository
            .finish_account_deletion(
                self.realm,
                current.verifier(),
                token.verifier(),
                browser.verifier(),
            )
            .await
    }
}
