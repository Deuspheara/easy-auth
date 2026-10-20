use super::exchange::ISSUER;
use crate::{Error, OidcAuthorizationCode, Result, Secret};
use std::collections::HashSet;
use zeroize::Zeroizing;

const MAX_CALLBACK_BYTES: usize = 8192;
const MAX_VALUE_BYTES: usize = 2048;

/// Untrusted provider result, never identity or permission to consume pending state.
#[derive(Debug)]
pub enum GoogleAuthorizationOutcome {
    Code(OidcAuthorizationCode),
    Denied,
    ProviderFailure,
}

/// Bounded Google query decoding only. No network, storage, cancellation or grant.
/// Transports must bind actual route, state, private proof, browser, purpose and
/// current configuration through OAuthTransactions before acting on any outcome.
#[derive(Debug)]
pub struct GoogleAuthorizationResponse {
    state: Secret,
    issuer: String,
    outcome: GoogleAuthorizationOutcome,
}

impl GoogleAuthorizationResponse {
    /// Accept only the actual raw query, without `?`, a URL or a fragment.
    /// Supported members are deliberately closed; this is not a general OAuth
    /// decoder. Presentation metadata and foreign error details are discarded.
    pub fn parse(query: &str) -> Result<Self> {
        let fields = Fields::parse(query)?;
        let issuer = fields.issuer.ok_or(Error::Unauthorized)?;
        if issuer != ISSUER {
            return Err(Error::Unauthorized);
        }
        let state = Secret::parse(fields.state.ok_or(Error::Unauthorized)?.to_string())?;
        let outcome = match (fields.code, fields.error) {
            (Some(code), None) if !fields.error_details => {
                GoogleAuthorizationOutcome::Code(OidcAuthorizationCode::parse(code.to_string())?)
            }
            (None, Some(error)) if !error.is_empty() && error.is_ascii() => {
                if error.as_str() == "access_denied" {
                    GoogleAuthorizationOutcome::Denied
                } else {
                    GoogleAuthorizationOutcome::ProviderFailure
                }
            }
            _ => return Err(Error::Unauthorized),
        };
        Ok(Self {
            state,
            issuer,
            outcome,
        })
    }

    pub fn state(&self) -> &Secret {
        &self.state
    }

    /// Actual decoded response issuer, never synthesized from configuration.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Inspect the untrusted result to select consume versus bound cancellation.
    /// This classification establishes no authority or provider authenticity.
    pub fn outcome(&self) -> &GoogleAuthorizationOutcome {
        &self.outcome
    }

    /// Call only after binding the response to its initiated operation. Denial
    /// and provider failure must not cause a token POST or local session grant.
    pub fn into_outcome(self) -> GoogleAuthorizationOutcome {
        self.outcome
    }

    pub(super) fn into_parts(self) -> (Secret, String, GoogleAuthorizationOutcome) {
        (self.state, self.issuer, self.outcome)
    }
}

#[derive(Default)]
struct Fields {
    state: Option<Zeroizing<String>>,
    issuer: Option<String>,
    code: Option<Zeroizing<String>>,
    error: Option<Zeroizing<String>>,
    error_details: bool,
}

impl Fields {
    fn parse(query: &str) -> Result<Self> {
        if query.is_empty() || query.len() > MAX_CALLBACK_BYTES || !valid_encoding(query) {
            return Err(Error::Unauthorized);
        }
        let mut names = HashSet::new();
        let mut fields = Self::default();
        for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
            let value = Zeroizing::new(value.into_owned());
            if !names.insert(name.to_string())
                || value.len() > MAX_VALUE_BYTES
                || value.contains('\u{fffd}')
                || value.chars().any(char::is_control)
            {
                return Err(Error::Unauthorized);
            }
            match name.as_ref() {
                "state" => fields.state = Some(value),
                "iss" => fields.issuer = Some(value.to_string()),
                "code" => fields.code = Some(value),
                "error" => fields.error = Some(value),
                "error_description" | "error_uri" => fields.error_details = true,
                // Google's documented redirect metadata grants no authorization.
                "scope" | "authuser" | "hd" | "prompt" | "session_state" => {}
                _ => return Err(Error::Unauthorized),
            }
        }
        Ok(fields)
    }
}

fn valid_encoding(query: &str) -> bool {
    let bytes = query.as_bytes();
    bytes.iter().enumerate().all(|(index, byte)| {
        *byte != b'#'
            && (*byte != b'%'
                || bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                    && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit))
    })
}
