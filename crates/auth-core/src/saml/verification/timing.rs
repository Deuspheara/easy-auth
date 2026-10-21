use crate::{Error, Result};
use saml_rs::{AuthnSession, SamlInstant};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(super) const SECOND_US: i64 = 1_000_000;
pub(super) const MESSAGE_AGE_US: i64 = 300 * SECOND_US;
pub(super) const AUTHN_AGE_US: i64 = 24 * 60 * 60 * SECOND_US;

pub(super) fn instant(value: &SamlInstant) -> Result<i64> {
    i64::try_from(nanos(value)? / 1000).map_err(|_| Error::Unauthorized)
}

fn nanos(value: &SamlInstant) -> Result<i128> {
    Ok(OffsetDateTime::parse(value.as_str(), &Rfc3339)
        .map_err(|_| Error::Unauthorized)?
        .unix_timestamp_nanos())
}

pub(super) fn recent_instant(value: &SamlInstant, now: i64, age: i64) -> Result<i64> {
    // DB caps have microsecond precision. Compare the signed instant before
    // truncation so sub-microsecond future dates do not acquire implicit skew.
    if nanos(value)? > i128::from(now) * 1000 {
        return Err(Error::Unauthorized);
    }
    recent(instant(value)?, now, age)
}

pub(super) fn system(value: i64) -> Result<SystemTime> {
    let micros = u64::try_from(value).map_err(|_| Error::Unavailable)?;
    UNIX_EPOCH
        .checked_add(Duration::from_micros(micros))
        .ok_or(Error::Unavailable)
}

pub(super) fn micros(value: SystemTime) -> Result<i64> {
    i64::try_from(
        value
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unauthorized)?
            .as_micros(),
    )
    .map_err(|_| Error::Unauthorized)
}

pub(super) fn recent(value: i64, now: i64, age: i64) -> Result<i64> {
    let until = value.checked_add(age).ok_or(Error::Unauthorized)?;
    if value <= 0 || value > now || now >= until {
        return Err(Error::Unauthorized);
    }
    Ok(until)
}

/// Separate the short admission deadline from the maximum session derived from
/// signed authentication. Approved Errata 05 E26/E79 retain SessionNotOnOrAfter;
/// our fixed 24h authn-age policy is a further application limit.
pub(super) fn authentication_session(authn: &AuthnSession, now: i64) -> Result<(i64, i64)> {
    let instant = authn.authn_instant().ok_or(Error::Unauthorized)?;
    let authn_until = recent_instant(instant, now, AUTHN_AGE_US)?;
    let session_until = authn
        .not_on_or_after()
        .map(self::instant)
        .transpose()?
        .unwrap_or(authn_until)
        .min(authn_until);
    if session_until <= now {
        return Err(Error::Unauthorized);
    }
    Ok((self::instant(instant)?, session_until))
}
