use super::{
    policy::Policy,
    ports::{MAX_OIDC_DOCUMENT_BYTES, OidcHttpResponse},
};
use crate::{Error, OAuthConnection, OAuthMixupDefense, Result};
use serde::Deserialize;
use std::{fmt, sync::Arc};

const MAX_JWKS_KEYS: usize = 64;
const MAX_PKCE_METHODS: usize = 16;
const MAX_PKCE_METHOD_BYTES: usize = 64;
const PRIVATE_JWK_FIELDS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Bounded public-key envelope, never a verified signing key or identity proof.
/// Raw provider documents must not enter diagnostics.
#[derive(Clone)]
pub struct OidcJwksDocument(Arc<[u8]>);
impl OidcJwksDocument {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for OidcJwksDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcJwksDocument([REDACTED])")
    }
}

#[derive(Clone)]
pub struct OidcDiscovery {
    issuer: String,
    authorization: String,
    token: String,
    jwks: String,
    s256: bool,
    response_issuer: bool,
}
impl OidcDiscovery {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn authorization_endpoint(&self) -> &str {
        &self.authorization
    }
    pub fn token_endpoint(&self) -> &str {
        &self.token
    }
    pub fn jwks_uri(&self) -> &str {
        &self.jwks
    }
    pub fn supports_s256(&self) -> bool {
        self.s256
    }
    pub fn supports_response_issuer(&self) -> bool {
        self.response_issuer
    }
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
}

pub(super) fn discovery(
    response: OidcHttpResponse,
    connection: &OAuthConnection,
    policy: &Policy,
) -> Result<OidcDiscovery> {
    check_response(&response, false)?;
    let wire: Discovery = serde_json::from_slice(&response.body).map_err(|_| Error::Unavailable)?;
    if wire.issuer != connection.issuer()
        || wire.code_challenge_methods_supported.len() > MAX_PKCE_METHODS
        || wire
            .code_challenge_methods_supported
            .iter()
            .any(|method| method.len() > MAX_PKCE_METHOD_BYTES)
        || (connection.defense() == OAuthMixupDefense::RequireIssuer
            && !wire.authorization_response_iss_parameter_supported)
    {
        return Err(Error::Unavailable);
    }
    policy.endpoint(&wire.authorization_endpoint)?;
    policy.endpoint(&wire.token_endpoint)?;
    policy.endpoint(&wire.jwks_uri)?;
    Ok(OidcDiscovery {
        issuer: wire.issuer,
        authorization: wire.authorization_endpoint,
        token: wire.token_endpoint,
        jwks: wire.jwks_uri,
        s256: wire
            .code_challenge_methods_supported
            .iter()
            .any(|method| method == "S256"),
        response_issuer: wire.authorization_response_iss_parameter_supported,
    })
}

pub(super) fn jwks(response: OidcHttpResponse) -> Result<OidcJwksDocument> {
    check_response(&response, true)?;
    // Validate only the bounded envelope. Preserve original bytes for the later
    // reviewed JOSE verifier; never reserialize ambiguous/duplicate key fields.
    #[derive(Deserialize)]
    struct Envelope {
        keys: Vec<serde_json::Map<String, serde_json::Value>>,
    }
    let envelope: Envelope =
        serde_json::from_slice(&response.body).map_err(|_| Error::Unavailable)?;
    if envelope.keys.is_empty()
        || envelope.keys.len() > MAX_JWKS_KEYS
        || envelope.keys.iter().any(|key| {
            key.is_empty()
                || PRIVATE_JWK_FIELDS
                    .iter()
                    .any(|field| key.contains_key(*field))
        })
    {
        return Err(Error::Unavailable);
    }
    // Structural admission only. Private/symmetric key parameters must not enter a public JWKS cache.
    Ok(OidcJwksDocument(response.body.into()))
}

fn check_response(response: &OidcHttpResponse, keys: bool) -> Result<()> {
    let mime = response
        .content_type
        .as_deref()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if response.status != 200
        || response.body.len() > MAX_OIDC_DOCUMENT_BYTES
        || !(mime.eq_ignore_ascii_case("application/json")
            || (keys && mime.eq_ignore_ascii_case("application/jwk-set+json")))
        || response
            .content_encoding
            .as_deref()
            .is_some_and(|value| !value.trim().eq_ignore_ascii_case("identity"))
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}
