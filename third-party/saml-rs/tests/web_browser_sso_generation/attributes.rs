use super::*;
use saml_rs::{Attribute, AttributeValue, Attributes};

fn attributes() -> Attributes {
    Attributes::new(vec![
        Attribute::new(
            "department",
            Some("urn:example:format:one".into()),
            vec![
                AttributeValue::new("Engineering"),
                AttributeValue::new("Operations"),
                AttributeValue::new("Engineering"),
            ],
        ),
        Attribute::new(
            "department",
            Some("urn:example:format:two".into()),
            vec![AttributeValue::new("ordinary-value")],
        ),
        Attribute::new("department", None, vec![AttributeValue::new("")]),
        Attribute::new("department", Some(String::new()), Vec::new()),
        Attribute::new(
            "department",
            Some("urn:example:format:one".into()),
            vec![AttributeValue::new("last record")],
        ),
    ])
}

#[test]
fn signed_scalar_attribute_records_keep_format_order_and_duplicate_value_groups(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    for options in [
        RespondSso::post().sign_response(),
        RespondSso::post()
            .sign_response()
            .apply_web_browser_sso_generation_rules(),
    ] {
        let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
        let received = idp.receive_sso(
            &sp_descriptor,
            BrowserInput::<AuthnRequest>::post(started.outbound.post_form()?.fields().to_vec()),
            validation(),
        )?;
        let response = idp.respond_sso(
            &sp_descriptor,
            &received,
            subject(),
            options.attributes(attributes()),
        )?;
        let session = sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
            validation(),
        )?;
        assert_eq!(session.attribute_records(), Some(&attributes()));
    }
    Ok(())
}
