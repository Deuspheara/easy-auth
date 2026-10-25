use super::*;
use crate::{IssuerAuthority, IssuerClientRegistration, IssuerTokenError, Secret};
use uuid::Uuid;

#[test]
fn presented_credentials_are_bounded_redacted_and_distinct_from_minted_secret_parsing() {
    let secret = Secret::generate().unwrap();
    let parsed = IssuerPresentedToken::parse(secret.expose().to_owned()).unwrap();
    assert_eq!(parsed.verifier(), secret.verifier());
    assert_eq!(format!("{parsed:?}"), "IssuerPresentedToken([REDACTED])");
    assert!(IssuerPresentedToken::parse("unknown-opaque-token".to_owned()).is_ok());
    for input in [
        String::new(),
        "x".repeat(1025),
        "line\nbreak".to_owned(),
        "nonasciié".to_owned(),
    ] {
        assert!(IssuerPresentedToken::parse(input).is_err());
    }
}

fn data(authority: &IssuerAuthority, client: &IssuerClientRegistration) -> IssuerAccessData {
    IssuerAccessData {
        realm: authority.realm(),
        issuer: authority.issuer().to_owned(),
        client: client.client(),
        subject: Uuid::new_v4(),
        issued_at_us: 1_000_000,
        expires_at_us: 61_000_000,
        checked_at_us: 2_000_000,
    }
}
#[test]
fn active_port_output_must_keep_the_exact_namespace_audience_and_bounded_live_times() {
    let authority = IssuerAuthority::new(Uuid::new_v4(), "https://issuer.example").unwrap();
    let secret = Secret::generate().unwrap();
    let client = IssuerClientRegistration::confidential(
        authority.realm(),
        Uuid::new_v4(),
        &["https://app.example/cb"],
        &secret,
    )
    .unwrap();
    assert!(
        IssuerActiveAccess::from_repository(data(&authority, &client), &authority, &client).is_ok()
    );
    for field in [
        "realm", "issuer", "client", "subject", "issued", "expired", "long",
    ] {
        let mut value = data(&authority, &client);
        match field {
            "realm" => value.realm = Uuid::new_v4(),
            "issuer" => value.issuer = "https://other.example".to_owned(),
            "client" => value.client = Uuid::new_v4(),
            "subject" => value.subject = Uuid::nil(),
            "issued" => value.issued_at_us = value.checked_at_us + 1,
            "expired" => value.expires_at_us = value.checked_at_us,
            "long" => value.expires_at_us = value.issued_at_us + 301_000_000,
            _ => unreachable!(),
        }
        assert!(matches!(
            IssuerActiveAccess::from_repository(value, &authority, &client),
            Err(IssuerTokenError::Unavailable)
        ));
    }
}
