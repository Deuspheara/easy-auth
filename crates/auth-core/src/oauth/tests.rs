use super::*;
use crate::Secret;
use uuid::Uuid;

#[test]
fn rfc7636_s256_vector_and_secret_redaction() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let nonce = Secret::generate().unwrap();
    let proof = OAuthBrowserProof::parse(nonce.expose().to_owned(), verifier.to_owned()).unwrap();
    assert_eq!(
        proof.code_challenge(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    let debug = format!("{proof:?}");
    assert!(!debug.contains(verifier));
    assert!(!debug.contains(nonce.expose()));
    let other = OAuthBrowserProof::generate().unwrap();
    assert_ne!(other.nonce().verifier(), other.pkce_verifier().verifier());
    assert_ne!(proof.code_challenge(), other.code_challenge());
}

#[test]
fn configuration_and_callback_fail_closed_without_url_normalization() {
    let make = |issuer, redirect, defense| {
        OAuthConnection::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            issuer,
            "provider-client",
            redirect,
            defense,
        )
    };
    for issuer in [
        "http://idp.example",
        "https://user@idp.example",
        "https://idp.example#x",
        "https://idp.example?x",
        " https://idp.example",
    ] {
        assert!(
            make(
                issuer,
                "https://app.example/callback",
                OAuthMixupDefense::RequireIssuer
            )
            .is_err()
        );
    }
    let connection = make(
        "https://idp.example",
        "https://app.example/callback",
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    for redirect in [
        "https://APP.example/callback",
        "https://app.example:443/callback",
        "https://app.example/x/../callback",
        "https://app.example/a b",
    ] {
        assert!(
            make(
                connection.issuer(),
                redirect,
                OAuthMixupDefense::DedicatedRedirect
            )
            .is_err()
        );
    }
    for (redirect, issuer) in [
        (connection.redirect(), None),
        (connection.redirect(), Some("https://idp.example/")),
        ("https://app.example/other", Some(connection.issuer())),
        (connection.redirect(), Some("https://attacker.example")),
    ] {
        assert!(
            connection
                .validate_callback(&OAuthCallback { redirect, issuer })
                .is_err()
        );
    }
    connection
        .validate_callback(&OAuthCallback {
            redirect: connection.redirect(),
            issuer: Some(connection.issuer()),
        })
        .unwrap();
    let dedicated = make(
        connection.issuer(),
        connection.redirect(),
        OAuthMixupDefense::DedicatedRedirect,
    )
    .unwrap();
    dedicated
        .validate_callback(&OAuthCallback {
            redirect: dedicated.redirect(),
            issuer: None,
        })
        .unwrap();
    assert!(
        dedicated
            .validate_callback(&OAuthCallback {
                redirect: dedicated.redirect(),
                issuer: Some("https://attacker.example")
            })
            .is_err()
    );
}
