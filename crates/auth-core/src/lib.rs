//! Shared authentication use cases. HTTP and SQL implementations live outside this crate.
mod password;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
pub use password::{Password, PasswordService};
use rand::{RngCore, rngs::OsRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid input")]
    InvalidInput,
    #[error("authentication required")]
    Unauthorized,
    #[error("too many requests")]
    RateLimited,
    #[error("authentication temporarily unavailable")]
    Unavailable,
}
pub type Result<T> = std::result::Result<T, Error>;
pub type Verifier = [u8; 32];

/// A canonical 256-bit bearer secret. Intentionally neither Serialize nor Clone.
pub struct Secret(String);
impl Secret {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        let result = Self(URL_SAFE_NO_PAD.encode(bytes));
        bytes.zeroize();
        Ok(result)
    }
    pub fn parse(value: String) -> Result<Self> {
        if value.len() != 43 {
            return Err(Error::Unauthorized);
        }
        let mut bytes = URL_SAFE_NO_PAD
            .decode(&value)
            .map_err(|_| Error::Unauthorized)?;
        let canonical = bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&bytes) == value;
        bytes.zeroize();
        if !canonical {
            return Err(Error::Unauthorized);
        }
        Ok(Self(value))
    }
    /// Expose only at the transport boundary. Never log this value.
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn verifier(&self) -> Verifier {
        Sha256::digest(self.0.as_bytes()).into()
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Conservative ASCII mailbox policy, consistently case-insensitive. No plus/dot rewriting.
pub fn normalize_email(value: &str) -> Result<String> {
    if value.len() > 254 || !value.is_ascii() {
        return Err(Error::InvalidInput);
    }
    let (local, domain) = value.split_once('@').ok_or(Error::InvalidInput)?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(Error::InvalidInput);
    }
    Ok(value.to_ascii_lowercase())
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub email: String,
}

/// Non-secret, purpose-specific delivery work. Never exposed through the HTTP API.
pub struct PasswordResetNotice {
    pub id: Uuid,
    pub lease: Uuid,
    pub recipient: String,
}

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
    async fn admit_password(&self, realm: Uuid, email: &str, source: Verifier) -> Result<()>;
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
    async fn claim_password_reset_notice(&self, realm: Uuid)
    -> Result<Option<PasswordResetNotice>>;
    async fn complete_password_reset_notice(
        &self,
        realm: Uuid,
        id: Uuid,
        lease: Uuid,
        delivered: bool,
    ) -> Result<()>;
    async fn ready(&self) -> Result<()>;
}
#[async_trait]
pub trait EmailDelivery: Send + Sync {
    async fn sign_in(&self, email: &str, token: &Secret) -> Result<()>;
    async fn password_reset(&self, email: &str, token: &Secret) -> Result<()>;
    async fn password_changed(&self, email: &str) -> Result<()>;
}

#[derive(Clone)]
pub struct Auth {
    realm: Uuid,
    repository: Arc<dyn Repository>,
    email: Arc<dyn EmailDelivery>,
    passwords: Option<Arc<PasswordService>>,
}
impl Auth {
    pub fn new(
        realm: Uuid,
        repository: Arc<dyn Repository>,
        email: Arc<dyn EmailDelivery>,
    ) -> Self {
        Self {
            realm,
            repository,
            email,
            passwords: None,
        }
    }
    /// Enable passwords with an explicitly supplied compromised-password policy.
    pub fn with_passwords(mut self, passwords: Arc<PasswordService>) -> Self {
        self.passwords = Some(passwords);
        self
    }
    pub async fn enroll_password(
        &self,
        current: &Secret,
        password: Password,
        source: &str,
    ) -> Result<Secret> {
        let policy = self.passwords.as_ref().ok_or(Error::Unavailable)?;
        let user = self.authenticate(current).await?;
        self.repository
            .admit_password(
                self.realm,
                &user.email,
                Sha256::digest(source.as_bytes()).into(),
            )
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
    /// Deliver at most one leased non-secret notice. SMTP errors leave durable retry work.
    /// Call repeatedly from a bounded worker in both embedded and standalone compositions.
    pub async fn deliver_password_reset_notice(&self) -> Result<bool> {
        let Some(notice) = self
            .repository
            .claim_password_reset_notice(self.realm)
            .await?
        else {
            return Ok(false);
        };
        let delivery = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.email.password_changed(&notice.recipient),
        )
        .await
        .unwrap_or(Err(Error::Unavailable));
        self.repository
            .complete_password_reset_notice(self.realm, notice.id, notice.lease, delivery.is_ok())
            .await?;
        delivery.map(|_| true)
    }
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
    pub async fn authenticate(&self, session: &Secret) -> Result<User> {
        self.repository
            .authenticate(self.realm, session.verifier())
            .await
    }
    pub async fn logout(&self, session: &Secret) -> Result<()> {
        self.repository.revoke(self.realm, session.verifier()).await
    }
    pub async fn ready(&self) -> Result<()> {
        self.repository.ready().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokens_are_canonical_redacted_and_high_entropy() {
        let a = Secret::generate().unwrap();
        let b = Secret::generate().unwrap();
        assert_eq!(a.expose().len(), 43);
        assert_ne!(a.verifier(), b.verifier());
        assert_eq!(
            Secret::parse(a.expose().to_owned()).unwrap().verifier(),
            a.verifier()
        );
        assert_eq!(format!("{a:?}"), "Secret([REDACTED])");
        for invalid in ["x".repeat(42), "!".repeat(43), "A".repeat(42) + "B"] {
            assert!(Secret::parse(invalid).is_err());
        }
    }
    #[test]
    fn mailbox_policy_is_explicit() {
        assert_eq!(
            normalize_email("Alice+tag@EXAMPLE.com").unwrap(),
            "alice+tag@example.com"
        );
        for invalid in [
            "x",
            " x@example.com",
            "a..b@example.com",
            "a@-bad.com",
            "a@b..com",
            "a@b@c.com",
            "a\r\n@b.com",
            "a@b",
            "é@b.com",
        ] {
            assert!(normalize_email(invalid).is_err(), "{invalid:?}");
        }
    }
}
