use super::*;
use uuid::Uuid;

fn native(values: &[&str]) -> crate::Result<IssuerClientRegistration> {
    IssuerClientRegistration::public_native_loopback(Uuid::new_v4(), Uuid::new_v4(), values)
}

#[test]
fn native_admits_only_the_registered_literal_interface_and_path_across_ports() {
    let c = native(&["http://127.0.0.1:42001/return", "http://[::1]:42002/return"]).unwrap();
    assert_eq!(c.redirect_profile(), IssuerRedirectProfile::NativeLoopback);
    assert_eq!(c.kind(), IssuerClientKind::Public);
    assert_eq!(c.secret_verifier(), None);
    assert_eq!(
        c.redirects(),
        ["http://127.0.0.1/return", "http://[::1]/return"]
    );
    for value in [
        "http://127.0.0.1:49152/return",
        "http://[::1]:65535/return",
        "http://127.0.0.1/return",
        "http://127.0.0.1:80/return",
        "http://[::1]:80/return",
    ] {
        assert!(c.permits_redirect(value));
    }
    for value in [
        "https://127.0.0.1:49152/return",
        "http://localhost:49152/return",
        "http://127.0.0.2:49152/return",
        "http://[::ffff:127.0.0.1]:49152/return",
        "http://127.0.0.1:49152/other",
        "http://127.0.0.1:49152/return/",
        "http://127.0.0.1:49152/return?q=1",
        "http://127.0.0.1:49152/return#fragment",
        "http://user@127.0.0.1:49152/return",
        "http://127.0.0.1:0/return",
        "http://2130706433:49152/return",
        "http://127.0.0.1:00080/return",
        "http://127.0.0.1:49152/a/../return",
        "http://127.0.0.1:49152/return\n",
    ] {
        assert!(!c.permits_redirect(value));
    }
    let v4 = native(&["http://127.0.0.1/return"]).unwrap();
    assert!(!v4.permits_redirect("http://[::1]:49152/return"));
}

#[test]
fn native_registration_rejects_mixed_ambiguous_or_unbounded_metadata() {
    for value in [
        "https://app.example/return",
        "app:/return",
        "http://localhost/return",
        "http://0.0.0.0/return",
        "http://127.0.0.1/",
        "http://127.0.0.1/return?x=1",
        "http://127.0.0.1/return#fragment",
        "http://127.0.0.1:0/return",
        "http://user:pass@127.0.0.1/return",
        "http://127.1/return",
        "http://[::]/return",
    ] {
        assert!(native(&[value]).is_err());
    }
    assert!(native(&[]).is_err());
    assert!(native(&["http://127.0.0.1/return"; MAX_ISSUER_REDIRECTS + 1]).is_err());
    assert!(
        native(&[
            "http://127.0.0.1:41001/return",
            "http://127.0.0.1:41002/return"
        ])
        .is_err()
    );
    assert!(native(&["http://127.0.0.1/return", "https://app.example/return"]).is_err());
    assert!(
        native(&[&format!(
            "http://127.0.0.1/{}",
            "x".repeat(MAX_ISSUER_REDIRECT_BYTES)
        )])
        .is_err()
    );
}

#[test]
fn native_sector_is_stable_for_one_client_and_isolated_from_other_native_clients() {
    let realm = Uuid::new_v4();
    let id = Uuid::new_v4();
    let first =
        IssuerClientRegistration::public_native_loopback(realm, id, &["http://127.0.0.1/return"])
            .unwrap();
    let changed =
        IssuerClientRegistration::public_native_loopback(realm, id, &["http://[::1]:41001/other"])
            .unwrap();
    assert_eq!(first.sector(), changed.sector());
    assert_eq!(first.reconfigured().sector(), first.sector());
    assert_ne!(
        first.sector(),
        native(&["http://127.0.0.1/return"]).unwrap().sector()
    );
    assert!(IssuerClientRegistration::public(realm, id, &["http://127.0.0.1/return"]).is_err());
    let secret = crate::Secret::generate().unwrap();
    assert!(
        IssuerClientRegistration::confidential(realm, id, &["http://127.0.0.1/return"], &secret)
            .is_err()
    );
}
