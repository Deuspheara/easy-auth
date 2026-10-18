use super::Auth;
use crate::{Error, Password, Result, Secret, normalize_email};
use sha2::{Digest, Sha256};

impl Auth {
    pub async fn start_password_reset(&self, email: &str, source: &str) -> Result<Secret> {
        self.passwords.as_ref().ok_or(Error::Unavailable)?;
        let email = normalize_email(email)?;
        self.repository
            .admit_password(self.realm, &email, Sha256::digest(source.as_bytes()).into())
            .await?;
        let token = Secret::generate()?;
        let browser = Secret::generate()?;
        self.repository
            .begin_password_reset(self.realm, &email, token.verifier(), browser.verifier())
            .await?;
        // Same delivery path whether or not this mailbox has a password credential.
        self.email.password_reset(&email, &token).await?;
        Ok(browser)
    }
    pub async fn finish_password_reset(
        &self,
        token: Secret,
        browser: Secret,
        password: Password,
        source: &str,
    ) -> Result<()> {
        let policy = self.passwords.as_ref().ok_or(Error::Unavailable)?;
        let email = self
            .repository
            .password_reset_email(self.realm, token.verifier(), browser.verifier())
            .await?;
        self.repository
            .admit_password(self.realm, &email, Sha256::digest(source.as_bytes()).into())
            .await?;
        let hash = policy.enroll(password).await?;
        self.repository
            .finish_password_reset(self.realm, token.verifier(), browser.verifier(), &hash)
            .await
    }
}
