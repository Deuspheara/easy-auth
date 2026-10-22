use super::*;

fn qualified_subject() -> Subject {
    Subject::new(
        NameId::with_qualifiers(
            "ordinary-subject",
            Some(NameIdFormat::Persistent),
            Some(IDP_ENTITY_ID.to_owned()),
            Some(SP_ENTITY_ID.to_owned()),
            Some("ordinary-alias".to_owned()),
        ),
        Vec::new(),
    )
}

#[test]
fn typed_signed_sso_preserves_all_nameid_qualifiers() -> Result<(), Box<dyn std::error::Error>> {
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
        let response = idp.respond_sso(&sp_descriptor, &received, qualified_subject(), options)?;
        let session = sp.finish_sso(
            &idp_descriptor,
            &started.pending,
            BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
            validation(),
        )?;
        assert_eq!(session.name_id().value(), "ordinary-subject");
        assert_eq!(session.name_id().format(), Some(&NameIdFormat::Persistent));
        assert_eq!(session.name_id().name_qualifier(), Some(IDP_ENTITY_ID));
        assert_eq!(session.name_id().sp_name_qualifier(), Some(SP_ENTITY_ID));
        assert_eq!(session.name_id().sp_provided_id(), Some("ordinary-alias"));
    }
    Ok(())
}

#[test]
fn typed_qualified_nameid_refuses_legacy_custom_rendering() -> Result<(), Box<dyn std::error::Error>>
{
    let sp = sp_with(signing_sp_validation())?;
    let mut config = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .credentials(credentials())
        .validation(signed_authn_request_idp_validation())
        .build()?;
    config.templates.login_response_template = Some(LoginResponseTemplate {
        context: Some(LOGIN_RESPONSE_TEMPLATE.to_owned()),
        attributes: Vec::new(),
    });
    let idp = Saml::idp(config)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    assert!(matches!(
        idp.initiate_sso(&sp_descriptor, qualified_subject(), RespondSso::post()),
        Err(SamlError::Invalid(message)) if message.contains("qualified NameID requires")
    ));
    Ok(())
}
