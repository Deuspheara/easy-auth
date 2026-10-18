//! Bounded Argon2id work and local compromised-password policy.
use crate::{Error, Result};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt, sync::Arc};
use tokio::sync::Semaphore;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// NFC-normalized password. Never Debug/Serialize the plaintext.
pub struct Password(Zeroizing<String>);
impl Password {
    pub fn parse(value: String) -> Result<Self> {
        let value = Zeroizing::new(value);
        if value.len() > 1024 {
            return Err(Error::InvalidInput);
        }
        let normalized = Zeroizing::new(value.nfc().collect::<String>());
        if normalized.len() > 1024 || !(15..=256).contains(&normalized.chars().count()) {
            return Err(Error::InvalidInput);
        }
        Ok(Self(normalized))
    }
}
impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password([REDACTED])")
    }
}
fn engine() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 1, Some(32)).expect("fixed Argon2 parameters"),
    )
}
fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
fn hash(value: &str) -> Result<String> {
    let mut salt = Zeroizing::new([0; 16]);
    OsRng
        .try_fill_bytes(&mut *salt)
        .map_err(|_| Error::Unavailable)?;
    let salt = SaltString::encode_b64(&*salt).map_err(|_| Error::Unavailable)?;
    engine()
        .hash_password(value.as_bytes(), &salt)
        .map(|v| v.to_string())
        .map_err(|_| Error::Unavailable)
}

/// Share one instance across a process's realms/routers to bound total hash memory.
/// Each of two workers uses 64 MiB; permits remain held if an HTTP request is canceled.
pub struct PasswordService {
    blocked: HashSet<[u8; 32]>,
    workers: Arc<Semaphore>,
    dummy: String,
}
impl PasswordService {
    /// Corpus consists of complete passwords, one per line. No network lookup on enrollment.
    /// Operators must supply a suitable corpus; a tiny example list is development-only.
    pub fn new(corpus: &str) -> Result<Self> {
        let mut blocked = HashSet::new();
        for line in corpus.lines() {
            if let Ok(password) = Password::parse(line.to_owned()) {
                blocked.insert(digest(&password.0));
            }
        }
        if blocked.is_empty() {
            return Err(Error::InvalidInput);
        }
        // A random dummy input prevents the dummy hash from being a known login credential.
        let dummy_input = crate::Secret::generate()?;
        Ok(Self {
            blocked,
            workers: Arc::new(Semaphore::new(2)),
            dummy: hash(dummy_input.expose())?,
        })
    }
    pub fn corpus_size(&self) -> usize {
        self.blocked.len()
    }
    pub async fn enroll(&self, password: Password) -> Result<Zeroizing<String>> {
        if self.blocked.contains(&digest(&password.0)) {
            return Err(Error::InvalidInput);
        }
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::RateLimited)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            hash(&password.0).map(Zeroizing::new)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
    pub async fn verify(&self, password: Password, stored: Option<String>) -> Result<bool> {
        let exists = stored.is_some();
        let stored = Zeroizing::new(stored.unwrap_or_else(|| self.dummy.clone()));
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::RateLimited)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let parsed = PasswordHash::new(&stored).map_err(|_| Error::Unavailable)?;
            // Reject malformed or unexpectedly costly hashes before running the KDF.
            if parsed.algorithm.as_str() != "argon2id"
                || parsed.version != Some(19)
                || parsed.params.get_decimal("m") != Some(65536)
                || parsed.params.get_decimal("t") != Some(3)
                || parsed.params.get_decimal("p") != Some(1)
                || parsed.params.iter().count() != 3
                || parsed.hash.as_ref().map(|h| h.len()) != Some(32)
                || parsed.salt.as_ref().map(|s| s.len()) != Some(22)
            {
                return Err(Error::Unavailable);
            }
            let valid = engine()
                .verify_password(password.0.as_bytes(), &parsed)
                .is_ok();
            Ok(valid && exists)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const GOOD: &str = "a long unique example password";
    #[tokio::test]
    async fn password_policy_hash_and_verification() {
        let service = PasswordService::new("a compromised example password").unwrap();
        assert!(Password::parse("short".into()).is_err());
        assert!(Password::parse("x".repeat(257)).is_err());
        assert!(Password::parse("x".repeat(1025)).is_err());
        assert!(Password::parse("🔒".repeat(64)).is_ok());
        assert!(Password::parse("é".repeat(256)).is_ok());
        assert!(Password::parse("this password has spaces".into()).is_ok());
        assert_eq!(
            format!("{:?}", Password::parse(GOOD.into()).unwrap()),
            "Password([REDACTED])"
        );
        assert!(
            service
                .enroll(Password::parse("a compromised example password".into()).unwrap())
                .await
                .is_err()
        );
        let a = service
            .enroll(Password::parse(GOOD.into()).unwrap())
            .await
            .unwrap();
        let b = service
            .enroll(Password::parse(GOOD.into()).unwrap())
            .await
            .unwrap();
        assert_ne!(*a, *b);
        assert!(a.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
        assert!(
            service
                .verify(Password::parse(GOOD.into()).unwrap(), Some(a.to_string()))
                .await
                .unwrap()
        );
        assert!(
            !service
                .verify(
                    Password::parse("another long example password".into()).unwrap(),
                    Some(a.to_string())
                )
                .await
                .unwrap()
        );
        assert!(
            !service
                .verify(Password::parse(GOOD.into()).unwrap(), None)
                .await
                .unwrap()
        );
        assert!(
            service
                .verify(
                    Password::parse(GOOD.into()).unwrap(),
                    Some(a.replace("m=65536", "m=999999"))
                )
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn normalization_and_capacity_are_explicit() {
        let composed = "é".repeat(15);
        let decomposed = "e\u{301}".repeat(15);
        let service = PasswordService::new(&composed).unwrap();
        assert!(
            service
                .enroll(Password::parse(decomposed).unwrap())
                .await
                .is_err()
        );
        let _one = service.workers.clone().acquire_owned().await.unwrap();
        let _two = service.workers.clone().acquire_owned().await.unwrap();
        assert!(matches!(
            service.enroll(Password::parse(GOOD.into()).unwrap()).await,
            Err(Error::RateLimited)
        ));
    }
}
