use super::*;
use openssl::x509::X509;

const IDP: &[u8] = include_bytes!("../../../../../tests/support/saml/certificates/idp.cer");
const ROTATION: &[u8] =
    include_bytes!("../../../../../tests/support/saml/certificates/rotation.cer");
const FROM: i64 = 1_483_228_800; // 2017-01-01 UTC, within upstream certificate validity.
const UNTIL: i64 = 1_514_764_800; // 2018-01-01 UTC.

fn pin(pem: &[u8]) -> SamlPinnedCertificate {
    let der = X509::from_pem(pem).unwrap().to_der().unwrap();
    SamlPinnedCertificate::from_der(&der, FROM, UNTIL).unwrap()
}

#[test]
fn exact_leaf_pins_have_explicit_validity_and_rotation_windows() {
    let first = pin(IDP);
    let second = pin(ROTATION);
    assert_ne!(first.fingerprint(), second.fingerprint());
    let trust = SamlCertificateTrust::pinned_leaf(vec![first.clone(), second]).unwrap();
    assert!(trust.active_at(FROM - 1).is_err());
    assert_eq!(trust.active_at(FROM).unwrap().len(), 2);
    assert_eq!(trust.active_at(UNTIL - 1).unwrap().len(), 2);
    assert!(trust.active_at(UNTIL).is_err());
    assert!(trust.active_at(1_792_540_800).is_err()); // 2026-10-21 UTC.
    assert!(SamlCertificateTrust::pinned_leaf(vec![first.clone(), first]).is_err());
    assert!(SamlCertificateTrust::pinned_leaf(vec![]).is_err());
}

#[test]
fn approval_cannot_outlive_certificate_or_accept_invalid_configuration() {
    let pin = pin(IDP);
    assert!(SamlPinnedCertificate::from_der(pin.der(), 0, UNTIL).is_err());
    assert!(SamlPinnedCertificate::from_der(pin.der(), FROM, 1_792_540_800).is_err());
    assert!(SamlPinnedCertificate::from_der(pin.der(), UNTIL, FROM).is_err());
    assert!(SamlPinnedCertificate::from_der(b"not a certificate", FROM, UNTIL).is_err());
    assert!(SamlCertificateTrust::pinned_leaf(vec![pin.clone(); 3]).is_err());
    let restored = SamlPinnedCertificate::from_der(pin.der(), FROM, UNTIL).unwrap();
    assert_eq!(restored.fingerprint(), pin.fingerprint());
    assert_eq!(
        format!("{restored:?}"),
        "SamlPinnedCertificate([configured certificate])"
    );
}
