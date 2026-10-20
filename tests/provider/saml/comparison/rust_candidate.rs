//! Research-only adapter over existing public APIs, not a SAML verification implementation.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use saml_rs::constants::{Binding, ParserType};
use saml_rs::crypto::verify_signature;
use saml_rs::flow::{flow, FlowOptions, HttpRequest};
use saml_rs::xml::dom::{self, Node};
use saml_rs::SamlError;
use std::io::{self, BufRead, Read};

fn main() {
    if run().is_err() {
        eprintln!("comparison_transport_failed");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().take(2 * 1024 * 1024).lines() {
        let line = line?;
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 4 {
            return Err("invalid_transport_row".into());
        }
        let xml = String::from_utf8(STANDARD.decode(fields[2])?)?;
        let certs: Vec<_> = fields[3]
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        emit(
            fields[0],
            fields[1],
            "raw-signature",
            verify_signature(&xml, &certs)
                .map(|(verified, content)| if verified { content } else { None }),
        );
        let mut opts = FlowOptions::default();
        opts.binding = Some(Binding::Post);
        opts.parser_type = Some(ParserType::SamlResponse);
        opts.check_signature = true;
        opts.strict_xml_signature_profile = true;
        opts.signing_certs = &certs;
        opts.from_issuer = Some("https://idp.example.test");
        opts.expected_audience = Some("https://sp.example.test");
        opts.expected_in_response_to = Some("auth32-owned-request");
        let request = HttpRequest {
            body: vec![("SAMLResponse".to_owned(), STANDARD.encode(xml.as_bytes()))],
            ..Default::default()
        };
        emit(
            fields[0],
            fields[1],
            "strict-flow",
            flow(&opts, &request).map(|value| Some(value.saml_content)),
        );
    }
    Ok(())
}

fn emit(case: &str, mode: &str, api: &str, result: Result<Option<String>, SamlError>) {
    let (accepted, subject, attacker, wrapper, error) = match result {
        Ok(Some(content)) => (
            true,
            trusted_subject(&content),
            content.contains("auth32-untrusted-subject"),
            content.contains("auth32-unsigned-envelope"),
            "none",
        ),
        Ok(None) => (false, false, false, false, "unverified"),
        Err(error) => (false, false, false, false, classify(&error)),
    };
    println!("{{\"case\":\"{case}\",\"mode\":\"{mode}\",\"api\":\"{api}\",\"accepted\":{accepted},\"trusted_subject\":{subject},\"attacker_marker\":{attacker},\"wrapper_marker\":{wrapper},\"error_class\":\"{error}\"}}");
}

fn trusted_subject(xml: &str) -> bool {
    let Ok(document) = dom::parse(xml) else {
        return false;
    };
    let root = &document.root;
    let assertion = if root.local_name == "Assertion" {
        Some(root)
    } else {
        root.children
            .iter()
            .find(|node| node.local_name == "Assertion")
    };
    assertion
        .and_then(|node| child(node, "Subject"))
        .and_then(|node| child(node, "NameID"))
        .is_some_and(|node| node.text == "auth32-trusted-subject")
}

fn child<'a>(node: &'a Node, name: &str) -> Option<&'a Node> {
    node.children.iter().find(|node| node.local_name == name)
}

fn classify(error: &SamlError) -> &'static str {
    match error {
        SamlError::Xml(_) => "xml_rejected",
        SamlError::PotentialWrappingAttack | SamlError::SignedReferenceMismatch => {
            "coverage_rejected"
        }
        SamlError::NoTrustedCertificate | SamlError::CertificateMismatch => "trust_rejected",
        SamlError::SignatureVerification { .. } | SamlError::SignatureMissing => {
            "signature_rejected"
        }
        SamlError::ReferenceResolution { .. } => "reference_rejected",
        SamlError::Crypto(_) => "crypto_error_unresolved",
        SamlError::AlgorithmUnsupported => "algorithm_rejected",
        SamlError::ProtocolProfile(_) => "protocol_profile_rejected",
        SamlError::SubjectConfirmationInvalid { .. } => "subject_confirmation_rejected",
        SamlError::TimeWindowInvalid { .. } => "time_rejected",
        _ => "other_rejection_unresolved",
    }
}
