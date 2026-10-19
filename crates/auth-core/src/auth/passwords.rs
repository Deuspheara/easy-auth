use super::Auth;
use crate::{AuthenticationPolicy, Error, Password, Result, Secret, normalize_email};
use sha2::{Digest, Sha256};

impl Auth {
    pub async fn enroll_password(
        &self,
        current: &Secret,
        password: Password,
        source: &str,
    ) -> Result<Secret> {
        let policy = self.passwords.as_ref().ok_or(Error::Unavailable)?;
        let user = self.authenticate(current).await?;
        if user.authentication_policy != AuthenticationPolicy::Mailbox {
            return Err(Error::Unauthorized);
        }
        let email = user.email.as_deref().ok_or(Error::Unauthorized)?;
        self.repository
            .admit_password(self.realm, email, Sha256::digest(source.as_bytes()).into())
            .await?;
        let hash = policy.enroll(password).await?;
        let replacement = Secret::generate()?;
        self.repository
            .enroll_password(
                self.realm,
                current.verifier(),
                &hash,
                replacement.verifier(),
            )
            .await?;
        Ok(replacement)
    }
    pub async fn password_login(
        &self,
        email: &str,
        password: Password,
        source: &str,
    ) -> Result<Secret> {
        let policy = self.passwords.as_ref().ok_or(Error::Unavailable)?;
        let email = normalize_email(email).map_err(|_| Error::Unauthorized)?;
        self.repository
            .admit_password(self.realm, &email, Sha256::digest(source.as_bytes()).into())
            .await?;
        let stored = self.repository.password_hash(self.realm, &email).await?;
        if !policy.verify(password, stored.clone()).await? {
            return Err(Error::Unauthorized);
        }
        let stored = zeroize::Zeroizing::new(stored.ok_or(Error::Unauthorized)?);
        let session = Secret::generate()?;
        self.repository
            .password_login(self.realm, &email, &stored, session.verifier())
            .await?;
        Ok(session)
    }
}
