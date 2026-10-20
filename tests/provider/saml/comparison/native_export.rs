//! Private synthetic corpus transport only; never a verification result.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use samael::crypto::{CertificateDer, ReduceMode};

pub(super) fn emit(case: &str, mode: ReduceMode, xml: &str, certs: &[CertificateDer]) {
    let mode = match mode {
        ReduceMode::PreDigest => "predigest",
        ReduceMode::ValidateAndMarkNoAncestors => "rooted",
        _ => unreachable!("legacy mode is not used by this corpus"),
    };
    let certificates = certs
        .iter()
        .map(|cert| format!("\"{}\"", STANDARD.encode(cert.der_data())))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "{{\"case\":\"{case}\",\"mode\":\"{mode}\",\"xml_b64\":\"{}\",\"certs_b64\":[{certificates}]}}",
        STANDARD.encode(xml)
    );
}
