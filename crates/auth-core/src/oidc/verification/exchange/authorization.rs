use crate::{Error, OAuthConnection, OAuthStart, OidcDiscovery, Result};
use std::fmt;
use zeroize::Zeroizing;

const MAX_SCOPES: usize = 16;
const MAX_SCOPE_BYTES: usize = 64;
const RESERVED: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "max_age",
    "prompt",
];

pub struct OidcAuthorizationUrl(Zeroizing<String>);
impl OidcAuthorizationUrl {
    /// Deliberate browser redirect boundary; never log the URL/state/nonce.
    pub fn expose(&self) -> &str {
        &self.0
    }
    /// Fixed account selection for the explicit Google linking operation. This
    /// is a user-choice request, never evidence of recent provider authentication.
    #[cfg(all(feature = "google", feature = "oidc-linking"))]
    pub(in crate::oidc) fn with_google_account_selection(mut self) -> Result<Self> {
        let mut url = url::Url::parse(&self.0).map_err(|_| Error::Unavailable)?;
        if url
            .query_pairs()
            .any(|(name, _)| name.eq_ignore_ascii_case("prompt"))
        {
            return Err(Error::Unavailable);
        }
        url.query_pairs_mut()
            .append_pair("prompt", "select_account");
        self.0 = Zeroizing::new(url.into());
        Ok(self)
    }
    #[cfg(feature = "google")]
    pub(in crate::oidc) fn with_google_session_age(mut self) -> Result<Self> {
        let mut url = url::Url::parse(&self.0).map_err(|_| Error::Unavailable)?;
        if url
            .query_pairs()
            .any(|(name, _)| name.eq_ignore_ascii_case("claims"))
        {
            return Err(Error::Unavailable);
        }
        url.query_pairs_mut()
            .append_pair("claims", r#"{"id_token":{"auth_time":{"essential":true}}}"#);
        self.0 = Zeroizing::new(url.into());
        Ok(self)
    }
    pub(super) fn new(
        discovery: &OidcDiscovery,
        connection: &OAuthConnection,
        start: &OAuthStart,
        scopes: &[&str],
        reauthenticate: bool,
        redirect: &str,
    ) -> Result<Self> {
        if !connection.permits_return(redirect) {
            return Err(Error::InvalidInput);
        }
        if !discovery.supports_s256() {
            return Err(Error::Unavailable);
        }
        if scopes.len() > MAX_SCOPES
            || scopes.iter().enumerate().any(|(i, value)| {
                value.is_empty()
                    || value.len() > MAX_SCOPE_BYTES
                    || scopes[..i].contains(value)
                    || !value.bytes().all(|b| {
                        b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b)
                    })
            })
        {
            return Err(Error::InvalidInput);
        }
        let mut url =
            url::Url::parse(discovery.authorization_endpoint()).map_err(|_| Error::Unavailable)?;
        validate_endpoint(&url)?;
        let mut accepted = vec!["openid"];
        accepted.extend(scopes.iter().copied().filter(|value| *value != "openid"));
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", connection.provider_client())
            .append_pair("redirect_uri", redirect)
            .append_pair("scope", &accepted.join(" "))
            .append_pair("state", start.state.expose())
            .append_pair("nonce", start.proof.nonce().expose())
            .append_pair("code_challenge", &start.proof.code_challenge())
            .append_pair("code_challenge_method", "S256");
        if reauthenticate {
            url.query_pairs_mut()
                .append_pair("max_age", "0")
                .append_pair("prompt", "login");
        }
        Ok(Self(Zeroizing::new(url.into())))
    }
}
impl fmt::Debug for OidcAuthorizationUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcAuthorizationUrl([REDACTED])")
    }
}

pub(in crate::oidc) fn validate_endpoint(url: &url::Url) -> Result<()> {
    if url.query_pairs().any(|(key, _)| {
        key.chars().any(char::is_control) || RESERVED.contains(&key.to_ascii_lowercase().as_str())
    }) {
        return Err(Error::Unavailable);
    }
    Ok(())
}
