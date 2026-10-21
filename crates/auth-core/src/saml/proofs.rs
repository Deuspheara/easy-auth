use crate::{Result, Secret};
use std::fmt;
use zeroize::Zeroizing;

/// Independent private browser proof. RelayState/request ID alone cannot cancel
/// an operation. Transport must protect this as a host-bound HttpOnly cookie.
#[derive(Debug)]
pub struct SamlBrowserProof(pub(super) Secret);

impl SamlBrowserProof {
    pub fn parse(value: String) -> Result<Self> {
        Secret::parse(value).map(Self)
    }
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

/// A committed outgoing request, never evidence of verified authentication.
pub struct SamlStart {
    pub(super) request_id: String,
    pub(super) authorization_url: Zeroizing<String>,
    pub(super) relay_state: Secret,
    pub(super) expires_at_ms: i64,
    pub(super) browser: SamlBrowserProof,
}

impl SamlStart {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    /// Contains protocol state; expose only to the initiating browser, never logs.
    pub fn authorization_url(&self) -> &str {
        &self.authorization_url
    }
    pub fn relay_state(&self) -> &Secret {
        &self.relay_state
    }
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
    pub fn browser_proof(&self) -> &SamlBrowserProof {
        &self.browser
    }
}

impl fmt::Debug for SamlStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SamlStart([REDACTED])")
    }
}
