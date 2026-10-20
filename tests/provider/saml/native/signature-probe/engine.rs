use super::fixture::{ATTACKER, TRUSTED, WRAPPER};
use libxml::parser::XmlParseError;
use samael::crypto::{
    AllowedSignatureAlgorithm, CertificateDer, Crypto, CryptoError, CryptoProvider, ReduceMode,
    XmlSecProviderError,
};
use samael::schema::{Assertion, Response};

pub(super) fn emit(case: &str, mode: ReduceMode, xml: &str, certs: &[CertificateDer]) {
    let name = match mode {
        ReduceMode::PreDigest => "predigest",
        ReduceMode::ValidateAndMarkNoAncestors => "rooted",
        _ => unreachable!("legacy reduction is never selected by this fixture"),
    };
    let result = Crypto::reduce_xml_to_signed_with_allowed_algorithms(
        xml,
        certs,
        mode,
        Some(&[AllowedSignatureAlgorithm::RsaSha256]),
    );
    let (accepted, trusted, attacker, wrapper, error) = match result {
        Ok(output) => {
            let trusted = output
                .parse::<Response>()
                .ok()
                .and_then(|response| response.assertion)
                .or_else(|| output.parse::<Assertion>().ok())
                .and_then(|assertion| assertion.subject)
                .and_then(|subject| subject.name_id)
                .is_some_and(|name| name.value == TRUSTED);
            (
                true,
                trusted,
                output.contains(ATTACKER),
                output.contains(WRAPPER),
                "none",
            )
        }
        Err(error) => (false, false, false, false, classify(&error)),
    };
    // All strings are fixed case/mode/error labels; no XML, keys or foreign errors escape.
    println!(
        r#"{{"case":"{case}","mode":"{name}","accepted":{accepted},"trusted_subject":{trusted},"attacker_marker":{attacker},"wrapper_marker":{wrapper},"error_class":"{error}"}}"#
    );
}

fn classify(error: &CryptoError) -> &'static str {
    match error {
        CryptoError::InvalidSignature => "invalid_signature",
        CryptoError::Base64Error { .. } => "invalid_encoding",
        CryptoError::CryptoProviderError(error) => {
            if error.downcast_ref::<XmlParseError>().is_some() {
                return "xml_parse";
            }
            match error.downcast_ref::<XmlSecProviderError>() {
                Some(XmlSecProviderError::XmlDuplicateIdAttribute { .. }) => "duplicate_id",
                Some(XmlSecProviderError::XmlInvalidIdAttribute { .. }) => "invalid_id",
                Some(XmlSecProviderError::XmlReferenceResolutionError { .. }) => {
                    "reference_rejected"
                }
                _ => "engine_error",
            }
        }
        _ => "engine_error",
    }
}
