use super::{
    cases::emit,
    fixture::{self, Result, Signer, ATTACKER, TRUSTED, WRAPPER},
};

pub(super) fn run(signer: &Signer, other: &Signer) -> Result<()> {
    let signed = signer.sign_assertion()?;
    let certs = std::slice::from_ref(&signer.cert);
    emit("assertion-healthy-before", &signed.xml, certs);
    emit(
        "assertion-wrong-key",
        &signed.xml,
        std::slice::from_ref(&other.cert),
    );
    emit("assertion-missing-key", &signed.xml, &[]);
    emit(
        "assertion-unsigned",
        &fixture::unsigned(&signed.xml)?,
        certs,
    );
    emit(
        "assertion-altered-signature",
        &fixture::altered_signature(&signed.xml)?,
        certs,
    );
    if signed.xml.matches(TRUSTED).count() != 1 || !signed.xml.contains(WRAPPER) {
        return Err("owned_assertion_markers_invalid".into());
    }
    emit(
        "assertion-tampered-subject",
        &signed.xml.replace(TRUSTED, ATTACKER),
        certs,
    );
    sibling_cases(&signed.xml, &signed.signed_id, certs)?;
    emit("assertion-healthy-after", &signed.xml, certs);
    Ok(())
}

fn sibling_cases(
    xml: &str,
    signed_id: &str,
    certs: &[samael::crypto::CertificateDer],
) -> Result<()> {
    let assertion_start = "<saml2:Assertion ";
    let assertion_end = "</saml2:Assertion>";
    if xml.matches(assertion_start).count() != 1 || xml.matches(assertion_end).count() != 1 {
        return Err("owned_assertion_boundary_invalid".into());
    }
    let forged = format!("<saml2:Assertion xmlns:saml2='urn:oasis:names:tc:SAML:2.0:assertion' ID='auth32-forged-assertion'><saml2:Subject><saml2:NameID>{ATTACKER}</saml2:NameID></saml2:Subject></saml2:Assertion>");
    emit(
        "assertion-forged-before",
        &xml.replacen(assertion_start, &format!("{forged}{assertion_start}"), 1),
        certs,
    );
    emit(
        "assertion-forged-after",
        &xml.replacen(assertion_end, &format!("{assertion_end}{forged}"), 1),
        certs,
    );
    let duplicate = format!("<probe ID='{signed_id}'>{ATTACKER}</probe>");
    emit(
        "assertion-duplicate-id",
        &xml.replacen(assertion_end, &format!("{assertion_end}{duplicate}"), 1),
        certs,
    );
    Ok(())
}
