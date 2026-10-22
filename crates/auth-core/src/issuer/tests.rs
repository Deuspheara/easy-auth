use super::*;
use crate::Secret;
use uuid::Uuid;

#[test]
fn redirects_match_exact_bytes_and_fixed_query() {
    let c = IssuerClientRegistration::public(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &[
            "https://app.example/callback?mode=web",
            "https://app.example/other",
        ],
    )
    .unwrap();
    assert_eq!(c.sector(), "app.example");
    assert!(c.permits_redirect("https://app.example/callback?mode=web"));
    for other in [
        "https://app.example/callback",
        "https://app.example/callback?mode=WEB",
        "https://app.example/other/",
        "https://app.example:443/other",
        "https://other.example/other",
    ] {
        assert!(!c.permits_redirect(other));
    }
    assert_eq!(c.kind(), IssuerClientKind::Public);
    assert_eq!(c.secret_verifier(), None);
}

#[test]
fn registration_rejects_unsupported_or_ambiguous_redirects() {
    for value in [
        "",
        "http://app.example/callback",
        "https://app.example/callback#fragment",
        "https://user@app.example/callback",
        "https://*.example/callback",
        "https://app.example:443/callback",
        "https://APP.example/callback",
        "https://app.example/a/../callback",
        "https://127.0.0.1/callback",
        "https://[::1]/callback",
        "https://app.example./callback",
        "https://bad_host.example/callback",
        "https://-app.example/callback",
        "https://app..example/callback",
        "https://app.example/call back",
        "https://app.example/\ncallback",
        "custom:/callback",
    ] {
        assert!(
            IssuerClientRegistration::public(Uuid::new_v4(), Uuid::new_v4(), &[value]).is_err()
        );
    }
    for values in [
        vec![],
        vec!["https://app.example/cb"; 2],
        vec!["https://app.example/cb"; MAX_ISSUER_REDIRECTS + 1],
        vec!["https://app.example/cb", "https://other.example/cb"],
    ] {
        assert!(IssuerClientRegistration::public(Uuid::new_v4(), Uuid::new_v4(), &values).is_err());
    }
}

#[test]
fn client_metadata_redacts_credentials_and_replacement_is_fresh() {
    let secret = Secret::generate().unwrap();
    let c = IssuerClientRegistration::confidential(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &["https://app.example/cb"],
        &secret,
    )
    .unwrap();
    assert_eq!(c.kind(), IssuerClientKind::ConfidentialBasic);
    assert_eq!(c.secret_verifier(), Some(secret.verifier()));
    let debug = format!("{c:?}");
    assert!(!debug.contains(secret.expose()));
    assert!(!debug.contains("secret_verifier"));
    assert!(!debug.contains("https://"));
    let next = c.reconfigured();
    assert_ne!(c.revision(), next.revision());
    assert_eq!(c.redirects(), next.redirects());
    assert_eq!(c.secret_verifier(), next.secret_verifier());
}

#[test]
fn scope_and_redirect_bounds_are_explicit() {
    assert!(
        IssuerClientRegistration::public(Uuid::nil(), Uuid::new_v4(), &["https://app.example/cb"])
            .is_err()
    );
    assert!(
        IssuerClientRegistration::public(Uuid::new_v4(), Uuid::nil(), &["https://app.example/cb"])
            .is_err()
    );
    let redirects: Vec<_> = (0..MAX_ISSUER_REDIRECTS)
        .map(|i| format!("https://app.example/cb/{i}"))
        .collect();
    let values: Vec<_> = redirects.iter().map(String::as_str).collect();
    assert!(IssuerClientRegistration::public(Uuid::new_v4(), Uuid::new_v4(), &values).is_ok());
    let prefix = "https://app.example/";
    let maximum = format!(
        "{prefix}{}",
        "a".repeat(MAX_ISSUER_REDIRECT_BYTES - prefix.len())
    );
    assert!(IssuerClientRegistration::public(Uuid::new_v4(), Uuid::new_v4(), &[&maximum]).is_ok());
    assert!(
        IssuerClientRegistration::public(Uuid::new_v4(), Uuid::new_v4(), &[&(maximum + "a")])
            .is_err()
    );
}
