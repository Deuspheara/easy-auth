use super::{replay::Reservations, subject, timing, verified::VerifiedSamlAssertion};
use crate::{Error, Result, SamlPinnedCertificate, SamlPreparedResponse};
use saml_rs::{SsoSession, VerifiedXmlSignatureCoverage as Coverage};
use zeroize::Zeroizing;

const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

pub(super) fn project(
    prepared: SamlPreparedResponse,
    session: SsoSession,
    reservations: Reservations,
    pin: &SamlPinnedCertificate,
    now: i64,
) -> Result<VerifiedSamlAssertion> {
    validate_shape(&prepared, &session)?;
    let subject = subject::persistent(prepared.registration(), session.name_id())?;
    let response_until = timing::recent_instant(
        session.response_issue_instant(),
        now,
        timing::MESSAGE_AGE_US,
    )?;
    let assertion_until = timing::recent_instant(
        session.assertion_issue_instant(),
        now,
        timing::MESSAGE_AGE_US,
    )?;
    let authn = session
        .authn_session()
        .authn_instant()
        .ok_or(Error::Unauthorized)?;
    let authn_until = timing::recent_instant(authn, now, timing::AUTHN_AGE_US)?;
    let authn_at_us = timing::instant(authn)?;
    let conditions_until = timing::instant(session.not_on_or_after().ok_or(Error::Unauthorized)?)?;
    if reservations.0.len() != 2 || conditions_until <= now || conditions_until > assertion_until {
        return Err(Error::Unauthorized);
    }
    let mut expires_at_us = prepared
        .expires_at_us()
        .min(response_until)
        .min(assertion_until)
        .min(authn_until)
        .min(conditions_until)
        .min(
            pin.approved_until()
                .checked_mul(timing::SECOND_US)
                .ok_or(Error::Unavailable)?,
        );
    for reservation in &reservations.0 {
        // A finite five-minute message profile bounds durable replay retention.
        if reservation.retain_until_us <= now || reservation.retain_until_us > assertion_until {
            return Err(Error::Unauthorized);
        }
        expires_at_us = expires_at_us.min(reservation.retain_until_us);
    }
    if expires_at_us <= now {
        return Err(Error::Unauthorized);
    }
    Ok(VerifiedSamlAssertion {
        registration: prepared.registration().clone(),
        subject: Zeroizing::new(subject),
        authn_at_us,
        expires_at_us,
        certificate: *pin.fingerprint(),
        replay: reservations.0,
    })
}

fn validate_shape(prepared: &SamlPreparedResponse, session: &SsoSession) -> Result<()> {
    let reg = prepared.registration();
    if session.issuer().as_str() != reg.idp_entity()
        || session.in_response_to().map(|id| id.as_str()) != Some(prepared.request_id())
        || !session
            .audience()
            .iter()
            .any(|aud| aud.as_str() == reg.sp_entity())
        || session.authn_sessions().len() != 1
        || session.subject().confirmations().len() != 1
        || session.replay_keys().len() != 2
    {
        return Err(Error::Unauthorized);
    }
    let mut response = false;
    let mut assertion = false;
    for signature in session.verified_xml_signatures() {
        if signature.algorithm_uri() != RSA_SHA256 {
            return Err(Error::Unauthorized);
        }
        match signature.coverage() {
            Coverage::ResponseRoot => response = true,
            Coverage::ConsumedAssertion => assertion = true,
            Coverage::ResponseRootAndConsumedAssertion => {
                response = true;
                assertion = true;
            }
        }
    }
    if !response || !assertion {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
