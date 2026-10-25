use crate::{Error, Result};
use serde::Serialize;
use uuid::Uuid;

/// Account authority is independent of optional contact information.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationPolicy {
    Mailbox,
    PasskeyRequired,
    ProviderRequired,
}

impl AuthenticationPolicy {
    /// Pure account-method policy, never authentication. Method and the explicit
    /// link marker must come from current authoritative source storage. Signature,
    /// credential, source, realm, owner/session and deadline checks remain required.
    pub fn permits_session_method(self, method: &str, explicitly_linked: bool) -> bool {
        match self {
            Self::Mailbox => {
                matches!(method, "email" | "password" | "passkey" | "legacy_unknown")
                    || (method == "oidc" && explicitly_linked)
            }
            Self::PasskeyRequired => method == "passkey",
            Self::ProviderRequired => matches!(method, "oidc" | "saml"),
        }
    }
}

impl TryFrom<&str> for AuthenticationPolicy {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "mailbox" => Ok(Self::Mailbox),
            "passkey_required" => Ok(Self::PasskeyRequired),
            "provider_required" => Ok(Self::ProviderRequired),
            _ => Err(Error::Unauthorized),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub authentication_policy: AuthenticationPolicy,
}
