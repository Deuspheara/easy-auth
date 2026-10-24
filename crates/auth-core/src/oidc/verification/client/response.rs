use super::{
    OidcClientError, OidcClientResult,
    tokens::{InitialTokens, OidcClientCredential, OidcClientCredentials},
};
use crate::{OidcIdToken, OidcTokenResponse};
use serde::Deserialize;
use zeroize::Zeroize;
const MAX_ACCESS_SECONDS: u64 = 300;
const MAX_REFRESH_SECONDS: u64 = 86_400;
#[derive(Deserialize)]
struct Wire {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
    #[serde(default, deserialize_with = "super::super::input::optional")]
    id_token: Option<String>,
    #[serde(default, deserialize_with = "super::super::input::optional")]
    refresh_token: Option<String>,
    #[serde(default, deserialize_with = "super::super::input::optional")]
    refresh_expires_in: Option<u64>,
    #[serde(default, deserialize_with = "super::super::input::optional")]
    error: Option<String>,
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(s) = &mut self.id_token {
            s.zeroize();
        }
        if let Some(s) = &mut self.refresh_token {
            s.zeroize();
        }
    }
}
pub(super) fn initial(
    response: OidcTokenResponse,
    offline: bool,
    started_us: i64,
) -> OidcClientResult<InitialTokens> {
    let mut wire = parse(response, offline)?;
    let id = OidcIdToken::parse(wire.id_token.take().ok_or(OidcClientError::Protocol)?)
        .map_err(|_| OidcClientError::InvalidToken)?;
    Ok(InitialTokens {
        id,
        credentials: credentials(wire, started_us)?,
    })
}
pub(super) fn rotated(
    response: OidcTokenResponse,
    started_us: i64,
) -> OidcClientResult<OidcClientCredentials> {
    let wire = parse(response, true)?;
    // Refresh never manufactures a new login or authentication time.
    if wire.id_token.is_some() {
        return Err(OidcClientError::Protocol);
    }
    credentials(wire, started_us)
}
fn parse(response: OidcTokenResponse, offline: bool) -> OidcClientResult<Wire> {
    let response = response.json().map_err(|_| OidcClientError::Protocol)?;
    if response.status != 200 {
        #[derive(Deserialize)]
        struct Failure {
            error: String,
        }
        let failure: Failure =
            serde_json::from_slice(&response.body).map_err(|_| OidcClientError::Protocol)?;
        return Err(match (response.status, failure.error.as_str()) {
            (401, "invalid_client") => OidcClientError::InvalidClient,
            (400, "invalid_grant") => OidcClientError::InvalidGrant,
            (429, _) => OidcClientError::RateLimited,
            (503, _) | (504, _) => OidcClientError::Unavailable,
            _ => OidcClientError::Protocol,
        });
    }
    let wire: Wire =
        serde_json::from_slice(&response.body).map_err(|_| OidcClientError::Protocol)?;
    if wire.error.is_some()
        || !wire.token_type.eq_ignore_ascii_case("Bearer")
        || wire.expires_in == 0
        || wire.expires_in > MAX_ACCESS_SECONDS
        || wire.scope
            != if offline {
                "openid offline_access"
            } else {
                "openid"
            }
        || wire.refresh_token.is_some() != offline
        || wire.refresh_expires_in.is_some() != offline
        || wire
            .refresh_expires_in
            .is_some_and(|v| v == 0 || v > MAX_REFRESH_SECONDS)
    {
        return Err(OidcClientError::Protocol);
    }
    Ok(wire)
}
fn credentials(mut wire: Wire, started_us: i64) -> OidcClientResult<OidcClientCredentials> {
    Ok(OidcClientCredentials {
        access: OidcClientCredential::parse(std::mem::take(&mut wire.access_token))?,
        refresh: wire
            .refresh_token
            .take()
            .map(OidcClientCredential::parse)
            .transpose()?,
        access_expires_us: expiry(started_us, wire.expires_in)?,
        refresh_expires_us: wire
            .refresh_expires_in
            .map(|v| expiry(started_us, v))
            .transpose()?,
    })
}

fn expiry(started: i64, seconds: u64) -> OidcClientResult<i64> {
    let delta: i64 = seconds
        .checked_mul(1_000_000)
        .and_then(|v| v.try_into().ok())
        .ok_or(OidcClientError::Protocol)?;
    started.checked_add(delta).ok_or(OidcClientError::Protocol)
}
