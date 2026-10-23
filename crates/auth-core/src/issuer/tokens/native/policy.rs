pub const ISSUER_NATIVE_SCOPE: &str = "openid offline_access";
use crate::{Error, IssuerAuthority, IssuerClientRegistration, IssuerRedirectProfile, Result};
use uuid::Uuid;

pub const MAX_NATIVE_REFRESH_LIFETIME_SECONDS: u32 = 7 * 24 * 60 * 60;
pub const MAX_NATIVE_REFRESH_IDLE_SECONDS: u32 = 24 * 60 * 60;
const MICROSECONDS_PER_SECOND: i64 = 1_000_000;

/// Trusted offline configuration, never a consent, refresh token or local-session
/// proof. Initial persistence is disabled; operations must lock the exact enabled
/// policy and client revision. A new policy never extends an existing grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerNativeRefreshPolicy {
    authority: IssuerAuthority,
    client: IssuerClientRegistration,
    revision: Uuid,
    lifetime_seconds: u32,
    idle_seconds: u32,
}
impl IssuerNativeRefreshPolicy {
    /// Native delegation preserves the actual supported account method. Legacy
    /// unknown sessions and cross-policy method changes cannot authorize refresh.
    pub fn permits_authentication(
        &self,
        policy: crate::AuthenticationPolicy,
        method: &str,
    ) -> bool {
        match policy {
            crate::AuthenticationPolicy::Mailbox => {
                matches!(method, "email" | "password" | "passkey")
            }
            crate::AuthenticationPolicy::PasskeyRequired => method == "passkey",
            crate::AuthenticationPolicy::ProviderRequired => matches!(method, "oidc" | "saml"),
        }
    }
    pub fn new(
        authority: IssuerAuthority,
        client: IssuerClientRegistration,
        lifetime_seconds: u32,
        idle_seconds: u32,
    ) -> Result<Self> {
        if authority.realm() != client.realm()
            || client.redirect_profile() != IssuerRedirectProfile::NativeRefreshLoopback
            || lifetime_seconds == 0
            || lifetime_seconds > MAX_NATIVE_REFRESH_LIFETIME_SECONDS
            || idle_seconds == 0
            || idle_seconds > MAX_NATIVE_REFRESH_IDLE_SECONDS
            || idle_seconds > lifetime_seconds
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            authority,
            client,
            revision: Uuid::new_v4(),
            lifetime_seconds,
            idle_seconds,
        })
    }
    pub fn authority(&self) -> &IssuerAuthority {
        &self.authority
    }
    pub fn client(&self) -> &IssuerClientRegistration {
        &self.client
    }
    pub fn revision(&self) -> Uuid {
        self.revision
    }
    pub fn lifetime_seconds(&self) -> u32 {
        self.lifetime_seconds
    }
    pub fn idle_seconds(&self) -> u32 {
        self.idle_seconds
    }
    /// Persistence replacement invalidates earlier snapshots, even for identical input.
    pub fn reconfigured(&self) -> Self {
        let mut next = self.clone();
        next.revision = Uuid::new_v4();
        next
    }
    /// Restore configuration facts only. Exact current enabled checks remain required.
    pub fn with_persisted_revision(mut self, revision: Uuid) -> Result<Self> {
        if revision.is_nil() {
            return Err(Error::InvalidInput);
        }
        self.revision = revision;
        Ok(self)
    }
    /// The source/session absolute cap is captured under the original fresh-owner
    /// lock. Cookie freshness and idle deadlines remain separate and unchanged.
    pub fn grant_expires_at_us(
        &self,
        consented_at_us: i64,
        source_absolute_cap_us: i64,
    ) -> Result<i64> {
        if consented_at_us < 0 || source_absolute_cap_us <= consented_at_us {
            return Err(Error::InvalidInput);
        }
        let configured = consented_at_us
            .checked_add(i64::from(self.lifetime_seconds) * MICROSECONDS_PER_SECOND)
            .ok_or(Error::InvalidInput)?;
        Ok(configured.min(source_absolute_cap_us))
    }
}
