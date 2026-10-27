use super::{AppleInitialProfile, exchange::ISSUER};
use crate::{Error, OidcAuthorizationCode, Result, Secret};
use std::collections::HashSet;
use zeroize::Zeroizing;

const MAX_CALLBACK_BYTES: usize = 32 * 1024;
const MAX_MEMBER_BYTES: usize = 2048;
const MAX_FRONTCHANNEL_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub enum AppleAuthorizationOutcome {
    Code {
        code: OidcAuthorizationCode,
        initial_profile: Option<AppleInitialProfile>,
    },
    Denied,
    ProviderFailure,
}
/// Strict untrusted form/native-return decoder, never a verified identity.
#[derive(Debug)]
pub struct AppleAuthorizationResponse {
    state: Secret,
    outcome: AppleAuthorizationOutcome,
}
impl AppleAuthorizationResponse {
    /// Actual form-urlencoded return only. The adapter must separately verify
    /// method/content type/body bound and actual dedicated route/private binding.
    pub fn parse(form: &str) -> Result<Self> {
        if form.is_empty() || form.len() > MAX_CALLBACK_BYTES || !valid_encoding(form) {
            return Err(Error::Unauthorized);
        }
        let mut names = HashSet::new();
        let (mut state, mut code, mut error, mut profile) = (None, None, None, None);
        let mut token_present = false;
        for (name, value) in url::form_urlencoded::parse(form.as_bytes()) {
            let value = Zeroizing::new(value.into_owned());
            let bound = match name.as_ref() {
                "id_token" => MAX_FRONTCHANNEL_TOKEN_BYTES,
                "user" => 4096,
                _ => MAX_MEMBER_BYTES,
            };
            if !names.insert(name.to_string())
                || value.len() > bound
                || value.contains('\u{fffd}')
                || value.chars().any(char::is_control)
            {
                return Err(Error::Unauthorized);
            }
            match name.as_ref() {
                "state" => state = Some(Secret::parse(value.to_string())?),
                "code" => code = Some(OidcAuthorizationCode::parse(value.to_string())?),
                "error" => error = Some(value),
                "iss" if value.as_str() == ISSUER => {}
                "user" => profile = Some(AppleInitialProfile::parse(&value)?),
                "id_token" if !value.is_empty() => token_present = true,
                _ => return Err(Error::Unauthorized),
            }
        }
        let outcome = match (code, error) {
            (Some(code), None) => AppleAuthorizationOutcome::Code {
                code,
                initial_profile: profile,
            },
            (None, Some(error))
                if profile.is_none() && !token_present && !error.is_empty() && error.is_ascii() =>
            {
                if error.as_str() == "user_cancelled_authorize" {
                    AppleAuthorizationOutcome::Denied
                } else {
                    AppleAuthorizationOutcome::ProviderFailure
                }
            }
            _ => return Err(Error::Unauthorized),
        };
        Ok(Self {
            state: state.ok_or(Error::Unauthorized)?,
            outcome,
        })
    }
    pub fn state(&self) -> &Secret {
        &self.state
    }
    pub fn outcome(&self) -> &AppleAuthorizationOutcome {
        &self.outcome
    }
    pub(super) fn into_parts(self) -> (Secret, AppleAuthorizationOutcome) {
        (self.state, self.outcome)
    }
}

fn valid_encoding(form: &str) -> bool {
    let bytes = form.as_bytes();
    bytes.iter().enumerate().all(|(i, b)| {
        *b != b'#'
            && (*b != b'%'
                || bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                    && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
    })
}
