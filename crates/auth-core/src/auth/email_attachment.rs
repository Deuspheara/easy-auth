use super::Auth;
use crate::{Result, Secret, normalize_email};

impl Auth {
    /// Prove a contact mailbox without granting mailbox login/recovery authority.
    pub async fn start_email_attachment(
        &self,
        current: &Secret,
        email: &str,
        source: &str,
    ) -> Result<Secret> {
        self.admit_sensitive_action(current, source).await?;
        let email = normalize_email(email)?;
        let token = Secret::generate()?;
        let browser = Secret::generate()?;
        self.repository
            .begin_email_attachment(
                self.realm,
                current.verifier(),
                &email,
                token.verifier(),
                browser.verifier(),
            )
            .await?;
        // Occupied and available targets take the same delivery path. The final
        // transaction rejects occupied addresses without linking or moving keys.
        self.email.email_attachment(&email, &token).await?;
        Ok(browser)
    }

    pub async fn finish_email_attachment(
        &self,
        current: &Secret,
        token: Secret,
        browser: Secret,
        source: &str,
    ) -> Result<Secret> {
        self.admit_sensitive_action(current, source).await?;
        let replacement = Secret::generate()?;
        self.repository
            .finish_email_attachment(
                self.realm,
                current.verifier(),
                token.verifier(),
                browser.verifier(),
                replacement.verifier(),
            )
            .await?;
        Ok(replacement)
    }
}
