use super::setup::Fixture;
use auth_core::{SamlPinnedCertificate, SamlPostResponse, SamlStart, SamlTransactions};
use saml_rs::{NameId, NameIdFormat};
use sqlx::PgPool;
use std::time::Duration;

#[path = "../../../../../tests/support/saml/provider.rs"]
mod provider;
pub(super) use provider::trust;

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
    SamlPostResponse::parse(response_field_from(f, start, name_id, issuer, lifetime)).unwrap()
}

/// Actual library-produced untrusted POST field, reusable for normal delivery
/// retries. No XML mutation, custom signature operation or proof construction.
pub(super) fn response_field_from(
    f: &Fixture,
    start: &SamlStart,
    name_id: NameId,
    issuer: &str,
    lifetime: Duration,
) -> String {
    provider::response_field_from(
        &f.registration,
        start.authorization_url(),
        name_id,
        issuer,
        lifetime,
    )
}

pub(super) fn alternate_pin() -> SamlPinnedCertificate {
    let pem = include_bytes!("../../../../../third-party/saml-rs/tests/fixtures/key/idp/cert2.cer");
    let der = openssl::x509::X509::from_pem(pem)
        .unwrap()
        .to_der()
        .unwrap();
    SamlPinnedCertificate::from_der(&der, 1_609_459_200, 1_893_456_000).unwrap()
}

#[cfg(feature = "saml-identities")]
pub(super) fn response_with(
    f: &Fixture,
    start: &SamlStart,
    subject: &str,
    options: saml_rs::RespondSso,
) -> SamlPostResponse {
    SamlPostResponse::parse(provider::response_field_with(
        &f.registration,
        start.authorization_url(),
        NameId::new(subject, Some(NameIdFormat::Persistent)),
        f.registration.idp_entity(),
        Duration::from_secs(180),
        options,
    ))
    .unwrap()
}
