use super::{OidcMappedIdentity, usable_display_name};
use crate::{Error, OAuthConnection, Result, VerifiedOidcIdentity};

const MAX_ALLOWED_ISSUERS: usize = 8;

/// Trusted opt-in for creating a new local owner, never for merging an existing
/// owner by email. Deny still permits resolving an already-bound subject later.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OidcJitPolicy {
    #[default]
    Deny,
    Allow,
}

/// One signed ID-token claim used only as initial display metadata. No fallback,
/// JSON paths, remote UserInfo lookup, role mapping or email-based ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcDisplayNameClaim {
    Subject,
    Name,
    PreferredUsername,
}

/// Immutable trusted policy for one exact persisted connection revision. This
/// value is not callback input and does not prove current database authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcIdentityPolicy {
    connection: OAuthConnection,
    allowed_issuers: Vec<String>,
    display_name: OidcDisplayNameClaim,
    jit: OidcJitPolicy,
}

impl OidcIdentityPolicy {
    /// A nonempty explicit tenant issuer allowlist is required, even when the
    /// connection already binds an issuer. Comparison retains exact spelling.
    pub fn new(
        connection: OAuthConnection,
        allowed_issuers: &[&str],
        display_name: OidcDisplayNameClaim,
    ) -> Result<Self> {
        if allowed_issuers.is_empty()
            || allowed_issuers.len() > MAX_ALLOWED_ISSUERS
            || !allowed_issuers.contains(&connection.issuer())
        {
            return Err(Error::InvalidInput);
        }
        for (index, issuer) in allowed_issuers.iter().enumerate() {
            OAuthConnection::validate_issuer(issuer)?;
            if issuer.contains('*') || allowed_issuers[..index].contains(issuer) {
                return Err(Error::InvalidInput);
            }
        }
        Ok(Self {
            connection,
            allowed_issuers: allowed_issuers
                .iter()
                .map(|value| (*value).into())
                .collect(),
            display_name,
            jit: OidcJitPolicy::Deny,
        })
    }

    /// Administrative opt-in. A persistence implementation must rotate the
    /// connection revision on policy changes before accepting another callback.
    #[must_use]
    pub fn with_jit(mut self, jit: OidcJitPolicy) -> Self {
        self.jit = jit;
        self
    }

    pub fn configuration(&self) -> &OAuthConnection {
        &self.connection
    }
    pub fn allowed_issuers(&self) -> &[String] {
        &self.allowed_issuers
    }
    pub fn display_name_claim(&self) -> OidcDisplayNameClaim {
        self.display_name
    }
    pub fn jit(&self) -> OidcJitPolicy {
        self.jit
    }

    /// Consume a verified proof into a mapped proof, never a local user/session.
    /// Database resolution must recheck current policy, deadlines and ownership.
    pub fn map(&self, identity: VerifiedOidcIdentity) -> Result<OidcMappedIdentity> {
        if identity.configuration() != &self.connection {
            return Err(Error::Unauthorized);
        }
        let display_name = match self.display_name {
            OidcDisplayNameClaim::Subject => Some(identity.subject()),
            OidcDisplayNameClaim::Name => identity.name(),
            OidcDisplayNameClaim::PreferredUsername => identity.preferred_username(),
        }
        .filter(|value| usable_display_name(value))
        .map(str::to_owned);
        Ok(OidcMappedIdentity::new(
            self.clone(),
            identity,
            display_name,
        ))
    }
}
