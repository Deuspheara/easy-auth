use auth_core::{SamlCertificateTrust, SamlPinnedCertificate, SamlRegistration};
use saml_rs::{
    AuthnRequest, AuthnRequestValidationPolicy, BrowserInput, CertificatePem, Credentials,
    EntityId, IdpConfig, IdpValidationPolicy, MetadataTrustPolicy, NameId, PrivateKeyPem,
    ReplayPolicy, RespondSso, Saml, SamlValidationContext, SpDescriptor, SsoEndpoint, Subject,
};
use std::time::{Duration, SystemTime};

// Unchanged public upstream interoperability fixture, NOT a deployed IdP key.
const CERT: &[u8] = include_bytes!(
    "../../../third-party/saml-rs/tests/fixtures/interop/shibboleth-idp-5.2.3/idp-signing-cert.pem"
);
const KEY: &str = include_str!(
    "../../../third-party/saml-rs/tests/fixtures/interop/shibboleth-idp-5.2.3/idp-signing-key.pem"
);

pub(crate) fn trust() -> SamlCertificateTrust {
    let der = openssl::x509::X509::from_pem(CERT)
        .unwrap()
        .to_der()
        .unwrap();
    SamlCertificateTrust::pinned_leaf(vec![
        SamlPinnedCertificate::from_der(&der, 1_785_000_000, 2_000_000_000).unwrap(),
    ])
    .unwrap()
}

/// Library-generated ordinary SSO producer; not deployed-IdP evidence.
pub(crate) fn response_field_from(
    reg: &SamlRegistration,
    authorization_url: &str,
    name_id: NameId,
    issuer: &str,
    lifetime: Duration,
) -> String {
    response_field_with(
        reg,
        authorization_url,
        name_id,
        issuer,
        lifetime,
        RespondSso::post()
            .sign_response()
            .apply_web_browser_sso_generation_rules(),
    )
}

pub(crate) fn response_field_with(
    reg: &SamlRegistration,
    authorization_url: &str,
    name_id: NameId,
    issuer: &str,
    lifetime: Duration,
    options: RespondSso,
) -> String {
    let idp = identity_provider(reg, issuer, lifetime);
    let sp = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(reg.sp_entity()).unwrap(),
        &reg.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
    .unwrap();
    let url = url::Url::parse(authorization_url).unwrap();
    // The received AuthnRequest has already committed unique outgoing state.
    // The library's request-side cache is only this independent IdP fixture.
    let received = idp
        .receive_sso(
            &sp,
            BrowserInput::<AuthnRequest>::redirect(url.query().unwrap()),
            SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility),
        )
        .unwrap();
    let response = idp
        .respond_sso(&sp, &received, Subject::new(name_id, vec![]), options)
        .unwrap();
    response
        .post_form()
        .unwrap()
        .fields()
        .iter()
        .find(|f| f.name() == "SAMLResponse")
        .unwrap()
        .value()
        .to_owned()
}

fn identity_provider(
    reg: &SamlRegistration,
    issuer: &str,
    lifetime: Duration,
) -> Saml<saml_rs::Idp> {
    let config = IdpConfig::builder(EntityId::try_new(issuer).unwrap())
        .sso_endpoint(SsoEndpoint::redirect(reg.sso()).unwrap())
        .credentials(Credentials {
            signing_key: Some(PrivateKeyPem::new(fixture_signing_key())),
            signing_certificate: Some(CertificatePem::new(
                String::from_utf8(CERT.to_vec()).unwrap(),
            )),
            ..Default::default()
        })
        .validation(IdpValidationPolicy {
            authn_requests: AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent,
            ..IdpValidationPolicy::recommended()
        })
        .issuance_lifetime(lifetime)
        .build()
        .unwrap();
    Saml::idp(config).unwrap()
}

fn fixture_signing_key() -> String {
    // Same public fixture key, encoded as PKCS#8 by OpenSSL for the selected
    // AWS-LC signer; no key material is generated or changed.
    let key = openssl::pkey::PKey::private_key_from_pem(KEY.as_bytes()).unwrap();
    String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap()
}
