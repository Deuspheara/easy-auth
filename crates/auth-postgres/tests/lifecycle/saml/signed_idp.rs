use super::setup::Fixture;
use auth_core::{
    SamlCertificateTrust, SamlPinnedCertificate, SamlPostResponse, SamlStart, SamlTransactions,
};
use saml_rs::{
    AuthnRequest, AuthnRequestValidationPolicy, BrowserInput, CertificatePem, Credentials,
    EntityId, IdpConfig, IdpValidationPolicy, MetadataTrustPolicy, NameId, NameIdFormat,
    PrivateKeyPem, ReplayPolicy, RespondSso, Saml, SamlValidationContext, SpDescriptor,
    SsoEndpoint, Subject,
};
use sqlx::PgPool;
use std::{time::Duration, time::SystemTime};

// Unchanged public upstream interoperability fixture, NOT a deployed IdP key.
const CERT: &[u8] = include_bytes!(
    "../../../../../third-party/saml-rs/tests/fixtures/interop/shibboleth-idp-5.2.3/idp-signing-cert.pem"
);
const KEY: &str = include_str!(
    "../../../../../third-party/saml-rs/tests/fixtures/interop/shibboleth-idp-5.2.3/idp-signing-key.pem"
);

pub(super) fn trust() -> SamlCertificateTrust {
    let der = openssl::x509::X509::from_pem(CERT)
        .unwrap()
        .to_der()
        .unwrap();
    SamlCertificateTrust::pinned_leaf(vec![
        SamlPinnedCertificate::from_der(&der, 1_785_000_000, 2_000_000_000).unwrap(),
    ])
    .unwrap()
}

pub(super) async fn fixture(pool: PgPool) -> Fixture {
    let mut f = Fixture::new(pool).await;
    f.registration = f
        .store
        .configure_saml_pinned_registration(&f.registration, &trust())
        .await
        .unwrap();
    f.flow = SamlTransactions::new(f.registration.clone(), f.store.clone());
    f
}

/// Use the established IdP facade and unchanged public key for an ordinary
/// signed browser SSO scenario; never edit XML or construct signature internals.
/// This is a local integration control, not Shibboleth interoperability evidence.
pub(super) fn response(
    f: &Fixture,
    start: &SamlStart,
    subject: &str,
    lifetime: Duration,
) -> SamlPostResponse {
    response_from(
        f,
        start,
        NameId::new(subject, Some(NameIdFormat::Persistent)),
        f.registration.idp_entity(),
        lifetime,
    )
}

pub(super) fn response_from(
    f: &Fixture,
    start: &SamlStart,
    name_id: NameId,
    issuer: &str,
    lifetime: Duration,
) -> SamlPostResponse {
    let reg = &f.registration;
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
    let idp = Saml::idp(config).unwrap();
    let sp = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(reg.sp_entity()).unwrap(),
        &reg.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
    .unwrap();
    let url = url::Url::parse(start.authorization_url()).unwrap();
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
        .respond_sso(
            &sp,
            &received,
            Subject::new(name_id, vec![]),
            RespondSso::post()
                .sign_response()
                .apply_web_browser_sso_generation_rules(),
        )
        .unwrap();
    let field = response
        .post_form()
        .unwrap()
        .fields()
        .iter()
        .find(|f| f.name() == "SAMLResponse")
        .unwrap()
        .value()
        .to_owned();
    SamlPostResponse::parse(field).unwrap()
}

fn fixture_signing_key() -> String {
    // Same public fixture key, encoded as PKCS#8 by OpenSSL for the selected
    // AWS-LC signer; no key material is generated or changed.
    let key = openssl::pkey::PKey::private_key_from_pem(KEY.as_bytes()).unwrap();
    String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap()
}

pub(super) fn alternate_pin() -> SamlPinnedCertificate {
    let pem = include_bytes!("../../../../../third-party/saml-rs/tests/fixtures/key/idp/cert2.cer");
    let der = openssl::x509::X509::from_pem(pem)
        .unwrap()
        .to_der()
        .unwrap();
    SamlPinnedCertificate::from_der(&der, 1_609_459_200, 1_893_456_000).unwrap()
}
