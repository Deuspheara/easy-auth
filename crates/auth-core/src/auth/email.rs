use super::Auth;
use crate::{Result, Secret, normalize_email};
use sha2::{Digest, Sha256};

impl Auth {
    pub async fn start_email(&self, email: &str, source: &str) -> Result<Secret> {
        let email = normalize_email(email)?;
        let token = Secret::generate()?;
        let browser = Secret::generate()?;
        let source_hash = Sha256::digest(source.as_bytes()).into();
        self.repository
            .begin_email(
                self.realm,
                &email,
                token.verifier(),
                browser.verifier(),
                source_hash,
            )
            .await?;
        self.email.sign_in(&email, &token).await?;
        Ok(browser)
    }
    pub async fn finish_email(&self, token: Secret, browser: Secret) -> Result<Secret> {
        let session = Secret::generate()?;
        self.repository
            .finish_email(
                self.realm,
                token.verifier(),
                browser.verifier(),
                session.verifier(),
            )
            .await?;
        Ok(session)
    }
}
