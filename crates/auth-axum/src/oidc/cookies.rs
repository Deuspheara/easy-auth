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
pub(super) const ACCOUNT_DELETION_COOKIES: Cookies = Cookies {
    names: [
        "__Host-auth-oidc-delete-browser",
        "__Host-auth-oidc-delete-state",
        "__Host-auth-oidc-delete-nonce",
        "__Host-auth-oidc-delete-pkce",
    ],
};
const COOKIE_SECONDS: u32 = 300;
#[cfg(feature = "oidc-web")]
pub(super) const SIGN_IN_COOKIES: Cookies = Cookies {
    names: [
        "__Host-auth-oidc-signin-browser",
        "__Host-auth-oidc-signin-state",
        "__Host-auth-oidc-signin-nonce",
        "__Host-auth-oidc-signin-pkce",
    ],
};

pub(super) struct Transaction {
    pub browser: Secret,
    pub state: Secret,
    pub proof: OAuthBrowserProof,
}
pub(super) struct Cookies {
    names: [&'static str; 4],
}

impl Cookies {
    #[cfg(feature = "oidc-web")]
    pub fn state_hint(&self, headers: &HeaderMap) -> Result<Option<Secret>> {
        read_optional_cookie(headers, self.names[1])
    }
    pub fn read(&self, headers: &HeaderMap) -> Result<Transaction> {
        Ok(Transaction {
            browser: read_cookie(headers, self.names[0])?,
            state: read_cookie(headers, self.names[1])?,
            proof: OAuthBrowserProof::parse(
                read_cookie(headers, self.names[2])?.expose().to_owned(),
                read_cookie(headers, self.names[3])?.expose().to_owned(),
            )?,
        })
    }

    pub fn require_absent(&self, headers: &HeaderMap) -> Result<()> {
        for name in self.names {
            if read_optional_cookie(headers, name)?.is_some() {
                // Explicit cancellation prevents overwriting a pending browser binding.
                return Err(Error::Unauthorized);
            }
        }
        Ok(())
    }
    pub fn set(
        &self,
        response: &mut Response,
        config: &BrowserConfig,
        browser: &Secret,
        start: &OAuthStart,
    ) {
        for (name, value) in self.names.into_iter().zip([
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
    pub fn clear(&self, response: &mut Response, config: &BrowserConfig) {
        for name in self.names {
            response
                .headers_mut()
                .append(header::SET_COOKIE, config.cookie(name, None, 0));
        }
    }
}

#[cfg(feature = "oidc-web")]
pub(super) fn require_anonymous(
    config: &BrowserConfig,
    headers: &HeaderMap,
) -> auth_core::Result<()> {
    for value in headers.get_all(header::COOKIE) {
        let value = value.to_str().map_err(|_| Error::Unauthorized)?;
        for pair in value.split(';').map(str::trim) {
            let name = pair.split_once('=').map_or(pair, |(name, _)| name);
            if name == config.session_name() {
                return Err(Error::Unauthorized);
            }
        }
    }
    Ok(())
}

pub(super) fn clear_revoked_proofs(
    response: &mut Response,
    config: &BrowserConfig,
    proofs: &[&Cookies],
) {
    let prefix = format!("{}=;", config.session_name());
    if response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|value| value.to_str().is_ok_and(|value| value.starts_with(&prefix)))
    {
        for proof in proofs {
            proof.clear(response, config);
        }
    }
}
