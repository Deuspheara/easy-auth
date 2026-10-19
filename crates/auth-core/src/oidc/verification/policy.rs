use crate::{Error, Result};
use serde::Deserialize;

pub(super) const MAX_AUDIENCES: usize = 8;
pub(super) const MAX_KID_BYTES: usize = 128;
const MAX_AUDIENCE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum OidcSigningAlgorithm {
    RS256,
    PS256,
    ES256,
}
impl OidcSigningAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::RS256 => "RS256",
            Self::PS256 => "PS256",
            Self::ES256 => "ES256",
        }
    }
}

/// Trusted configured policy. Additional audiences are explicit trust, never
/// copied from token input. Reapply configuration/revision when policy changes.
#[derive(Clone)]
pub struct OidcVerificationPolicy {
    pub(super) algorithms: Vec<OidcSigningAlgorithm>,
    pub(super) additional_audiences: Vec<String>,
}
impl OidcVerificationPolicy {
    pub fn new(algorithms: &[OidcSigningAlgorithm], additional_audiences: &[&str]) -> Result<Self> {
        if algorithms.is_empty()
            || algorithms.len() > 3
            || additional_audiences.len() >= MAX_AUDIENCES
        {
            return Err(Error::InvalidInput);
        }
        for (index, algorithm) in algorithms.iter().enumerate() {
            if algorithms[..index].contains(algorithm) {
                return Err(Error::InvalidInput);
            }
        }
        for (index, audience) in additional_audiences.iter().enumerate() {
            if audience.is_empty()
                || audience.len() > MAX_AUDIENCE_BYTES
                || audience.chars().any(char::is_control)
                || additional_audiences[..index].contains(audience)
            {
                return Err(Error::InvalidInput);
            }
        }
        Ok(Self {
            algorithms: algorithms.to_owned(),
            additional_audiences: additional_audiences
                .iter()
                .map(|v| (*v).to_owned())
                .collect(),
        })
    }
}
