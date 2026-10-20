use super::{
    engine,
    fixture::{self, Result, Signed, Signer, ATTACKER, TRUSTED, WRAPPER},
};
use samael::crypto::{CertificateDer, ReduceMode};
use samael::signature::DigestAlgorithm;

pub(super) fn run() -> Result<()> {
    let first = Signer::new()?;
    let second = Signer::new()?;
    let signed = first.sign(DigestAlgorithm::Sha256)?;
    let alternate = second.sign(DigestAlgorithm::Sha256)?;
    emit(
        "healthy-before",
        &signed.xml,
        std::slice::from_ref(&first.cert),
    );
    emit(
        "second-healthy",
        &alternate.xml,
        std::slice::from_ref(&second.cert),
    );
    trust_cases(&first, &second, &signed, &alternate)?;
    boundary_cases(&signed, std::slice::from_ref(&first.cert))?;
    emit(
        "healthy-after",
        &signed.xml,
        std::slice::from_ref(&first.cert),
    );
    Ok(())
}

fn trust_cases(first: &Signer, second: &Signer, signed: &Signed, alternate: &Signed) -> Result<()> {
    emit(
        "unsigned",
        &fixture::unsigned(&signed.xml)?,
        std::slice::from_ref(&first.cert),
    );
    emit(
        "altered-signature",
        &fixture::altered_signature(&signed.xml)?,
        std::slice::from_ref(&first.cert),
    );
    emit("wrong-key", &signed.xml, std::slice::from_ref(&second.cert));
    emit("missing-key", &signed.xml, &[]);
    emit(
        "untrusted-keyinfo",
        &alternate.xml,
        std::slice::from_ref(&first.cert),
    );
    emit(
        "rollover",
        &alternate.xml,
        &[first.cert.clone(), second.cert.clone()],
    );
    let legacy_digest = first.sign(DigestAlgorithm::Sha1)?;
    emit(
        "weak-digest",
        &legacy_digest.xml,
        std::slice::from_ref(&first.cert),
    );
    if signed.xml.matches(TRUSTED).count() != 1 {
        return Err("owned_subject_marker_not_unique".into());
    }
    emit(
        "tampered-subject",
        &signed.xml.replace(TRUSTED, ATTACKER),
        std::slice::from_ref(&first.cert),
    );
    Ok(())
}

fn boundary_cases(signed: &Signed, certs: &[CertificateDer]) -> Result<()> {
    let body = fixture::body(&signed.xml);
    let forged = format!(
        "<saml2:Assertion xmlns:saml2='urn:oasis:names:tc:SAML:2.0:assertion' ID='auth32-forged'><saml2:Subject><saml2:NameID>{ATTACKER}</saml2:NameID></saml2:Subject></saml2:Assertion>"
    );
    emit(
        "forged-sibling-before",
        &envelope(&format!("{forged}{body}")),
        certs,
    );
    emit(
        "forged-sibling-after",
        &envelope(&format!("{body}{forged}")),
        certs,
    );
    let duplicate = format!("<probe ID='{}'>{ATTACKER}</probe>", signed.response_id);
    emit(
        "duplicate-id",
        &envelope(&format!("{body}{duplicate}")),
        certs,
    );
    emit(
        "doctype",
        &format!("<!DOCTYPE saml2p:Response>{body}"),
        certs,
    );
    let malformed = body
        .strip_suffix('>')
        .ok_or("owned_response_close_missing")?;
    emit("malformed", malformed, certs);
    emit(
        "multiple-roots",
        &format!("{body}<extra>{ATTACKER}</extra>"),
        certs,
    );
    Ok(())
}

fn envelope(content: &str) -> String {
    format!("<owned:Envelope xmlns:owned='urn:auth32:wrapper' data-marker='{WRAPPER}'>{content}</owned:Envelope>")
}

fn emit(case: &str, xml: &str, certs: &[CertificateDer]) {
    for mode in [
        ReduceMode::ValidateAndMarkNoAncestors,
        ReduceMode::PreDigest,
    ] {
        engine::emit(case, mode, xml, certs);
    }
}
