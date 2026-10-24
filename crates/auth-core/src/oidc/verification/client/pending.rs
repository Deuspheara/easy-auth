use super::{OidcClientError, OidcClientResult, error::infrastructure};
use crate::Secret;
use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
use uuid::Uuid;
use zeroize::Zeroizing;

const PENDING_LIFETIME: Duration = Duration::from_secs(300);
/// One privately retained authorization operation. No Clone/Serialize or proof
/// constructor: successful callback consumption will move this value once.
pub struct OidcClientAuthorization {
    pub(super) configuration: Uuid,
    pub(super) state: Secret,
    pub(super) nonce: Secret,
    pub(super) pkce: Secret,
    pub(super) expires_us: i64,
    pub(super) deadline: Instant,
    pub(super) url: Zeroizing<String>,
}
impl OidcClientAuthorization {
    pub(super) fn new(configuration: Uuid) -> OidcClientResult<Self> {
        let now = now_us()?;
        Ok(Self {
            configuration,
            state: Secret::generate().map_err(infrastructure)?,
            nonce: Secret::generate().map_err(infrastructure)?,
            pkce: Secret::generate().map_err(infrastructure)?,
            expires_us: now
                .checked_add(PENDING_LIFETIME.as_micros() as i64)
                .ok_or(OidcClientError::Unavailable)?,
            deadline: Instant::now() + PENDING_LIFETIME,
            url: Zeroizing::new(String::new()),
        })
    }
    pub fn authorization_url(&self) -> &str {
        &self.url
    }
    pub(super) fn check(&self, configuration: Uuid) -> OidcClientResult<()> {
        if self.configuration != configuration {
            return Err(OidcClientError::Callback);
        }
        if Instant::now() >= self.deadline || now_us()? >= self.expires_us {
            return Err(OidcClientError::Expired);
        }
        Ok(())
    }
}
pub(super) fn now_us() -> OidcClientResult<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OidcClientError::Unavailable)?
        .as_micros()
        .try_into()
        .map_err(|_| OidcClientError::Unavailable)
}
impl fmt::Debug for OidcClientAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcClientAuthorization([REDACTED])")
    }
}
