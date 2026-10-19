use crate::{Result, Secret};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Transient browser proof, neither Serialize nor Clone. Retain the composite in
/// protected transport storage. Only nonce and S256 challenge go to the provider
/// authorization request; the raw PKCE verifier never goes into a URL or script storage.
#[derive(Debug)]
pub struct OAuthBrowserProof {
    nonce: Secret,
    pkce: Secret,
}

impl OAuthBrowserProof {
    pub(super) fn generate() -> Result<Self> {
        Ok(Self {
            nonce: Secret::generate()?,
            pkce: Secret::generate()?,
        })
    }
    /// Restore canonical values from the private transport, not provider input.
    pub fn parse(nonce: String, pkce: String) -> Result<Self> {
        Ok(Self {
            nonce: Secret::parse(nonce)?,
            pkce: Secret::parse(pkce)?,
        })
    }
    pub fn nonce(&self) -> &Secret {
        &self.nonce
    }
    /// Expose only for protected transport or a trusted token exchange.
    pub fn pkce_verifier(&self) -> &Secret {
        &self.pkce
    }
    /// RFC 7636 S256. The verifier is 32 random bytes encoded as 43 base64url chars.
    pub fn code_challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.pkce.verifier())
    }
}
