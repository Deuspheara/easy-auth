use crate::{BrowserConfig, browser::read_optional_cookie_value};
use auth_core::{Error, Result, SamlBrowserProof, SamlStart, Secret};
use axum::{
    http::{HeaderMap, header},
    response::Response,
};

pub(super) const SIGN_IN: ProofCookies = ProofCookies::new([
    "__Host-auth-saml-request",
    "__Host-auth-saml-relay",
    "__Host-auth-saml-browser",
]);
const LIFETIME_SECONDS: u32 = 300;

pub(super) struct Transaction {
    pub request: String,
    pub relay: Secret,
    pub browser: SamlBrowserProof,
}

/// Concrete SAML request/RelayState/private-browser transport. Fixed names are
/// supplied by trusted composition; the cookie policy and proof shape are shared.
pub(super) struct ProofCookies {
    names: [&'static str; 3],
}
impl ProofCookies {
    pub(super) const fn new(names: [&'static str; 3]) -> Self {
        Self { names }
    }
    pub(super) fn require_absent(&self, headers: &HeaderMap) -> Result<()> {
        for header in headers.get_all(header::COOKIE) {
            let header = header.to_str().map_err(|_| Error::Unauthorized)?;
            for pair in header.split(';').map(str::trim) {
                let name = pair.split_once('=').map_or(pair, |(name, _)| name);
                if self.names.contains(&name) {
                    return Err(Error::Unauthorized);
                }
            }
        }
        Ok(())
    }
    pub(super) fn read(&self, headers: &HeaderMap) -> Result<Transaction> {
        let value = |name| read_optional_cookie_value(headers, name)?.ok_or(Error::Unauthorized);
        let request = value(self.names[0])?;
        if !request.starts_with('_')
            || !(2..=128).contains(&request.len())
            || !request
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(Error::Unauthorized);
        }
        Ok(Transaction {
            request,
            relay: Secret::parse(value(self.names[1])?).map_err(|_| Error::Unauthorized)?,
            browser: SamlBrowserProof::parse(value(self.names[2])?)
                .map_err(|_| Error::Unauthorized)?,
        })
    }
    pub(super) fn set(&self, response: &mut Response, config: &BrowserConfig, start: &SamlStart) {
        for (name, value) in self.names.into_iter().zip([
            start.request_id(),
            start.relay_state().expose(),
            start.browser_proof().expose(),
        ]) {
            response.headers_mut().append(
                header::SET_COOKIE,
                config.cookie_value(name, Some(value), LIFETIME_SECONDS),
            );
        }
    }
    pub(super) fn clear(&self, response: &mut Response, config: &BrowserConfig) {
        for name in self.names {
            response
                .headers_mut()
                .append(header::SET_COOKIE, config.cookie_value(name, None, 0));
        }
    }
}

pub(super) fn clear_if_logged_out(response: &mut Response, config: &BrowserConfig) {
    let prefix = format!("{}=;", config.session_name());
    if response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().is_ok_and(|v| v.starts_with(&prefix)))
    {
        SIGN_IN.clear(response, config);
    }
}
