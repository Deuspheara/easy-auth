use auth_core::{Error, Result};
use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(in crate::saml) struct SamlDeletionConfirmation {
    /// Exact case-sensitive phrase: delete my account.
    #[schema(example = "delete my account")]
    pub confirmation: String,
}

// Provider input deliberately has no Debug or serialization contract.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(in crate::saml) struct SamlDeletionDelivery {
    #[serde(rename = "SAMLResponse")]
    #[schema(min_length = 1, max_length = 262144)]
    pub response: String,
    #[serde(rename = "RelayState")]
    #[schema(min_length = 43, max_length = 43)]
    pub relay: String,
    #[schema(example = "delete my account")]
    pub confirmation: String,
}

pub(super) fn confirm(value: &str) -> Result<()> {
    if value != "delete my account" {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
