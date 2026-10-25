use super::key::SigningKey;
use crate::{Error, OidcClientAuthentication, OidcClientSecret, Result};
use std::{fmt, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const APPLE_AUDIENCE: &str = "https://appleid.apple.com";
const SECRET_LIFETIME_SECONDS: u64 = 300;
const MAX_SIGNING_OPERATIONS: usize = 2;
const SIGNING_TIMEOUT: Duration = Duration::from_secs(15);

struct Material {
    key: SigningKey,
    key_id: String,
    team_id: String,
    client_id: String,
    not_before: u64,
    not_after: u64,
}

/// One explicitly selected operator key; replacement requires a new signer.
/// This creates backend client authentication only, never an identity/session.
pub struct AppleClientSecretSigner {
    material: Arc<Material>,
    workers: Arc<Semaphore>,
}

impl AppleClientSecretSigner {
    /// Protected PKCS8 P-256 input and UTC whole-second key-validity bounds.
    /// Team/key identifiers are Apple's ten-character uppercase identifiers.
    /// App/Services ID is exact and case-sensitive; no registration is inferred.
    pub fn from_pkcs8_pem(
        team_id: &str,
        client_id: &str,
        key_id: &str,
        not_before: u64,
        not_after: u64,
        pem: String,
    ) -> Result<Self> {
        // Wrap immediately, including rejected metadata paths.
        let mut pem = Zeroizing::new(pem);
        if !apple_identifier(team_id)
            || !apple_identifier(key_id)
            || !client_identifier(client_id)
            || not_before >= not_after
            || not_after > (i64::MAX / 1_000_000) as u64
        {
            return Err(Error::InvalidInput);
        }
        let key = SigningKey::parse(std::mem::take(&mut *pem))?;
        Ok(Self {
            material: Arc::new(Material {
                key,
                key_id: key_id.to_owned(),
                team_id: team_id.to_owned(),
                client_id: client_id.to_owned(),
                not_before,
                not_after,
            }),
            workers: Arc::new(Semaphore::new(MAX_SIGNING_OPERATIONS)),
        })
    }

    pub fn client_id(&self) -> &str {
        &self.material.client_id
    }

    /// Supply the authoritative operation clock, not a browser/token timestamp.
    /// Revalidate source/deadline after signing and before sending a secret.
    pub async fn issue(&self, now_us: i64) -> Result<AppleClientSecret> {
        let issued_at = u64::try_from(now_us / 1_000_000).map_err(|_| Error::Unavailable)?;
        if now_us < 0 {
            return Err(Error::Unavailable);
        }
        if issued_at < self.material.not_before || issued_at >= self.material.not_after {
            return Err(Error::Unauthorized);
        }
        let expires_at = issued_at
            .saturating_add(SECRET_LIFETIME_SECONDS)
            .min(self.material.not_after);
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::RateLimited)?;
        let material = self.material.clone();
        let work = tokio::task::spawn_blocking(move || {
            // Cancellation cannot release capacity while native signing continues.
            let _permit = permit;
            let payload = Zeroizing::new(
                serde_json::to_vec(&serde_json::json!({
                    "iss": material.team_id, "sub": material.client_id,
                    "aud": APPLE_AUDIENCE, "iat": issued_at, "exp": expires_at,
                }))
                .map_err(|_| Error::Unavailable)?,
            );
            Ok(AppleClientSecret {
                token: material.key.sign(&material.key_id, &payload)?,
                expires_at,
            })
        });
        tokio::time::timeout(SIGNING_TIMEOUT, work)
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)?
    }
}

/// Opaque short-lived backend secret. No Clone, serialization or public token
/// accessor; only the existing trusted token transport can expose its wire form.
pub struct AppleClientSecret {
    token: Zeroizing<String>,
    expires_at: u64,
}
impl AppleClientSecret {
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn into_client_authentication(mut self) -> Result<OidcClientAuthentication> {
        Ok(OidcClientAuthentication::ClientSecretPost(
            OidcClientSecret::parse(std::mem::take(&mut *self.token))?,
        ))
    }
}

impl fmt::Debug for AppleClientSecretSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppleClientSecretSigner([REDACTED])")
    }
}
impl fmt::Debug for AppleClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppleClientSecret([REDACTED])")
    }
}

fn apple_identifier(value: &str) -> bool {
    value.len() == 10
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}
fn client_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
