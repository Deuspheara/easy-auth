//! Exact policy regression scenarios using the existing signer and verifier.
use super::*;
use crate::constants::digest_algorithm::{SHA256, SHA384, SHA512};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn signed_pair(signature: &str, digest: &str, response: bool) -> TestResult<String> {
    let key = load_private_key(SP_PRIVKEY, None)?;
    let signed = construct_saml_signature(
        RESPONSE,
        response,
        &key,
        SP_SIGNING_CERT,
        signature,
        &[],
        None,
    )?;
    // Fixture construction only: change the requested digest, then recompute
    // both digest and signature using the existing provider before verification.
    let original = digest_for_signature(signature).ok_or("unknown fixture digest")?;
    sign_template(&empty_signature_values(&signed.replace(original, digest))?)
}

fn empty_signature_values(xml: &str) -> TestResult<String> {
    fn collect(node: &Node, replacements: &mut Vec<(usize, usize, String)>) {
        if matches!(node.local_name.as_str(), "DigestValue" | "SignatureValue") {
            replacements.push((
                node.start,
                node.end,
                format!("<ds:{0}></ds:{0}>", node.local_name),
            ));
        }
        for child in &node.children {
            collect(child, replacements);
        }
    }
    let document = dom::parse(xml)?;
    let mut replacements = Vec::new();
    collect(&document.root, &mut replacements);
    replacements.sort_by_key(|item| std::cmp::Reverse(item.0));
    let mut template = xml.to_owned();
    for (start, end, value) in replacements {
        template.replace_range(start..end, &value);
    }
    Ok(template)
}

#[test]
fn exact_policy_accepts_only_sha256_pairs_for_both_signature_targets() -> TestResult {
    for response in [true, false] {
        for (signature, digest) in [
            (RSA_SHA256, SHA256),
            (RSA_SHA384, SHA256),
            (RSA_SHA512, SHA256),
            (RSA_SHA256, SHA384),
            (RSA_SHA256, SHA512),
        ] {
            let signed = signed_pair(signature, digest, response)?;
            let trusted = [SP_SIGNING_CERT.to_owned()];
            let broad = verify_signatures_detailed_with_profile(
                &signed,
                &trusted,
                XmlLimits::default(),
                XmlSignatureProfile::StrictRsaSha2,
            )?;
            assert!(
                broad.verified(),
                "target_response={response}, signature={signature}, digest={digest}"
            );
            let exact = verify_signatures_detailed_with_profile(
                &signed,
                &trusted,
                XmlLimits::default(),
                XmlSignatureProfile::StrictRsaSha256,
            );
            if signature == RSA_SHA256 && digest == SHA256 {
                let result = exact?;
                assert!(result.verified());
                assert!(if response {
                    result.response_covered()
                } else {
                    result.assertion_directly_covered()
                });
            } else {
                assert!(matches!(exact, Err(SamlError::AlgorithmUnsupported)));
            }
        }
    }
    Ok(())
}

#[test]
fn exact_policy_uses_authenticated_content_not_unrelated_signature_algorithms() -> TestResult {
    let unrelated = signature_over_top_level_issuer(SP_PRIVKEY, SP_SIGNING_CERT, RSA_SHA512)?;
    let signed = assertion_signed_response_with_extra_signature(&root_signature(&unrelated)?)?;
    let result = verify_signatures_detailed_with_profile(
        &signed,
        &[SP_SIGNING_CERT.to_owned()],
        XmlLimits::default(),
        XmlSignatureProfile::StrictRsaSha256,
    )?;
    assert!(result.verified() && result.assertion_directly_covered());
    assert!(!result.response_covered());
    assert!(result
        .verified_embedded_signatures()
        .iter()
        .all(|value| value.algorithm_uri() == RSA_SHA256));
    Ok(())
}

#[test]
fn typed_sp_configuration_preserves_exact_profile() -> TestResult {
    use crate::{AcsEndpoint, EntityId, EntitySetting, SpConfig, SpValidationPolicy};
    let config = SpConfig::builder(EntityId::try_new("https://sp.example.test")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.test/acs")?)
        .validation(SpValidationPolicy {
            xml_signatures: XmlSignatureProfile::StrictRsaSha256,
            ..SpValidationPolicy::recommended()
        })
        .build()?;
    assert_eq!(
        EntitySetting::try_from(&config)?.xml_signature_profile,
        XmlSignatureProfile::StrictRsaSha256
    );
    Ok(())
}
