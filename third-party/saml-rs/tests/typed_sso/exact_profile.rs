//! Public typed SP propagation, with genuine signatures on both targets.
use super::*;
use saml_rs::constants::signature_algorithm::RSA_SHA384;

#[test]
fn typed_sp_enforces_exact_profile_before_exposing_a_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = recommended_post_exchange()?;
    let unsigned =
        strip_embedded_signatures(&response_xml_from_fields(&exchange.response_fields)?)?;
    let key = load_private_key(PRIVKEY, None)?;
    for response_target in [true, false] {
        for algorithm in [RSA_SHA256, RSA_SHA384, RSA_SHA512] {
            let signed = construct_saml_signature(
                &unsigned,
                response_target,
                &key,
                CERT,
                algorithm,
                &[],
                None,
            )?;
            let fields = response_fields_with_xml(exchange.response_fields.clone(), &signed)?;
            let broad = Saml::sp(sp_with_validation(SpValidationPolicy {
                xml_signatures: XmlSignatureProfile::StrictRsaSha2,
                ..recommended_sso_accept_validation()
            })?)?;
            broad.finish_sso(
                &exchange.idp_descriptor,
                &exchange.pending,
                BrowserInput::<SsoResponse>::post(fields.clone()),
                validation(),
            )?;
            let exact = Saml::sp(sp_with_validation(SpValidationPolicy {
                xml_signatures: XmlSignatureProfile::StrictRsaSha256,
                ..recommended_sso_accept_validation()
            })?)?;
            let result = exact.finish_sso(
                &exchange.idp_descriptor,
                &exchange.pending,
                BrowserInput::<SsoResponse>::post(fields),
                validation(),
            );
            if algorithm == RSA_SHA256 {
                let session = result?;
                assert_eq!(session.verified_xml_signatures().len(), 1);
                assert_eq!(
                    session.verified_xml_signatures()[0].algorithm_uri(),
                    RSA_SHA256
                );
            } else {
                assert!(matches!(result, Err(SamlError::AlgorithmUnsupported)));
            }
        }
    }
    Ok(())
}
