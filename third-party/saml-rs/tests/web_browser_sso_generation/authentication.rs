use super::*;
use saml_rs::SamlInstant;

#[test]
fn signed_new_sso_response_retains_established_authentication_time(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let previous = SamlInstant::try_new(saml_rs::entity::iso8601_offset(-600))?;
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
        RespondSso::post()
            .sign_response()
            .apply_web_browser_sso_generation_rules()
            .authentication_instant(previous.clone()),
    )?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(response.post_form()?.fields().to_vec()),
        validation(),
    )?;
    assert_eq!(session.authn_session().authn_instant(), Some(&previous));
    assert_ne!(session.assertion_issue_instant(), &previous);
    assert_ne!(session.response_issue_instant(), &previous);
    Ok(())
}

#[test]
fn established_authentication_cannot_silently_disappear_in_legacy_rendering(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with(signing_sp_validation())?;
    let idp = idp_with(signed_authn_request_idp_validation(), false)?;
    let (sp_descriptor, _) = descriptors(&sp, &idp)?;
    let previous = SamlInstant::try_new(saml_rs::entity::iso8601_offset(-600))?;
    assert!(matches!(
        idp.initiate_sso(
            &sp_descriptor,
            subject(),
            RespondSso::post().authentication_instant(previous)
        ),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}
