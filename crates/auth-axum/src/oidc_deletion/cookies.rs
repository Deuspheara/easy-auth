use crate::{
    BrowserConfig,
    browser::{read_cookie, read_optional_cookie},
};
use auth_core::{Error, OAuthBrowserProof, OAuthStart, Result, Secret};
use axum::{
    http::{HeaderMap, header},
    response::Response,
};

// This composition requires HTTPS. Each proof is independent, canonical, host-only
// and inaccessible to scripts. Database deadlines remain authoritative.
const NAMES: [&str; 4] = [
    "__Host-auth-oidc-delete-browser",
    "__Host-auth-oidc-delete-state",
    "__Host-auth-oidc-delete-nonce",
    "__Host-auth-oidc-delete-pkce",
];
const COOKIE_SECONDS: u32 = 300;

pub(super) struct Transaction {
    pub browser: Secret,
    pub state: Secret,
    pub proof: OAuthBrowserProof,
}
impl Transaction {
    pub fn read(headers: &HeaderMap) -> Result<Self> {
        Ok(Self {
            browser: read_cookie(headers, NAMES[0])?,
            state: read_cookie(headers, NAMES[1])?,
            proof: OAuthBrowserProof::parse(
                read_cookie(headers, NAMES[2])?.expose().to_owned(),
                read_cookie(headers, NAMES[3])?.expose().to_owned(),
            )?,
        })
    }
}

pub(super) fn require_absent(headers: &HeaderMap) -> Result<()> {
    for name in NAMES {
        if read_optional_cookie(headers, name)?.is_some() {
            // Explicit cancellation prevents overwriting a pending browser binding.
            return Err(Error::Unauthorized);
        }
    }
    Ok(())
}
pub(super) fn set(
    response: &mut Response,
    config: &BrowserConfig,
    browser: &Secret,
    start: &OAuthStart,
) {
    for (name, value) in NAMES.into_iter().zip([
        browser,
        &start.state,
        start.proof.nonce(),
        start.proof.pkce_verifier(),
    ]) {
        response.headers_mut().append(
            header::SET_COOKIE,
            config.cookie(name, Some(value), COOKIE_SECONDS),
        );
    }
}
pub(super) fn clear(response: &mut Response, config: &BrowserConfig) {
    for name in NAMES {
        response
            .headers_mut()
            .append(header::SET_COOKIE, config.cookie(name, None, 0));
    }
}
