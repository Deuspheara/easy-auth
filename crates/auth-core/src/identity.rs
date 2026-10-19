use crate::{Error, Result};
use serde::Serialize;
use uuid::Uuid;

/// Account authority is independent of optional contact information.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationPolicy {
    Mailbox,
    PasskeyRequired,
}

impl TryFrom<&str> for AuthenticationPolicy {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "mailbox" => Ok(Self::Mailbox),
            "passkey_required" => Ok(Self::PasskeyRequired),
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
