use super::{
    AppleGrantBinding, AppleGrantEnvelope, AppleGrantVault,
    payload::{GrantTokenKind, StoredGrant},
};
use crate::{
    Error, OAuthConnection, OidcIdentityPolicy, OidcMappedIdentity, Result, VerifiedOidcIdentity,
};
use std::fmt;
use zeroize::Zeroizing;

/// Only the same initiated, signature/nonce-verified Apple code exchange can
/// construct this result. It is not serializable or a token-upload API.
pub struct AppleVerifiedGrant {
    identity: VerifiedOidcIdentity,
    token: StoredGrant,
}
impl AppleVerifiedGrant {
    pub(in crate::oidc::apple) fn captured(
        identity: VerifiedOidcIdentity,
        mut token: Zeroizing<String>,
        access_expires_us: Option<i64>,
    ) -> Result<Self> {
        if identity.configuration().issuer() != super::super::exchange::ISSUER {
            return Err(Error::Unauthorized);
        }
        let token = StoredGrant {
            version: 1,
            kind: if access_expires_us.is_some() {
                GrantTokenKind::Access
            } else {
                GrantTokenKind::Refresh
            },
            token: std::mem::take(&mut *token),
            provider_client: identity.configuration().provider_client().to_owned(),
            access_expires_us,
        };
        token.validate()?;
        Ok(Self { identity, token })
    }
    pub fn identity(&self) -> &VerifiedOidcIdentity {
        &self.identity
    }
    pub fn map(self, policy: &OidcIdentityPolicy) -> Result<AppleMappedGrant> {
        let configuration = self.identity.configuration().clone();
        Ok(AppleMappedGrant {
            mapped: policy.map(self.identity)?,
            capture: AppleGrantCapture {
                configuration,
                token: self.token,
            },
        })
    }
}
impl fmt::Debug for AppleVerifiedGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppleVerifiedGrant([REDACTED])")
    }
}
pub struct AppleMappedGrant {
    mapped: OidcMappedIdentity,
    capture: AppleGrantCapture,
}
impl AppleMappedGrant {
    pub fn identity(&self) -> &OidcMappedIdentity {
        &self.mapped
    }
    /// Trusted repository boundary. No raw credential is exposed; the capture
    /// must be sealed using the identity actually resolved under existing locks.
    pub fn into_parts(self) -> (OidcMappedIdentity, AppleGrantCapture) {
        (self.mapped, self.capture)
    }
}
pub struct AppleGrantCapture {
    configuration: OAuthConnection,
    token: StoredGrant,
}
impl AppleGrantCapture {
    pub fn configuration(&self) -> &OAuthConnection {
        &self.configuration
    }
    pub async fn seal(
        self,
        binding: AppleGrantBinding,
        vault: &AppleGrantVault,
    ) -> Result<AppleGrantEnvelope> {
        let c = &self.configuration;
        if (binding.realm(), binding.connection(), binding.client())
            != (c.realm(), c.connection(), c.client())
        {
            return Err(Error::Unauthorized);
        }
        vault.seal(binding, self.token).await
    }
}
