use super::*;
use crate::{IssuerClientRegistration, Secret};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
fn input(client: Uuid) -> IssuerAuthorizationInput<'static> {
    IssuerAuthorizationInput {
        client,
        response_type: "code",
        redirect_uri: "https://app.example/cb",
        scope: "openid",
        state: "original-state",
        nonce: "original-nonce",
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
    }
}
fn web() -> (IssuerAuthority, IssuerClientRegistration) {
    let authority = IssuerAuthority::new(Uuid::new_v4(), "https://issuer.example").unwrap();
    let client = IssuerClientRegistration::public(
        authority.realm(),
        Uuid::new_v4(),
        &["https://app.example/cb"],
    )
    .unwrap();
    (authority, client)
}

#[test]
fn s256_uses_the_existing_published_vector_and_complete_verifier_length_range() {
    let verifier =
        IssuerPkceVerifier::parse("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned())
            .unwrap();
    assert_eq!(verifier.challenge(), CHALLENGE);
    assert_eq!(pkce::challenge(CHALLENGE).unwrap(), verifier.s256_digest());
    assert_eq!(format!("{verifier:?}"), "IssuerPkceVerifier([REDACTED])");
    for valid in ["~".repeat(43), ".".repeat(128)] {
        assert!(IssuerPkceVerifier::parse(valid).is_ok());
    }
    for invalid in [
        "x".repeat(42),
        "x".repeat(129),
        "!".repeat(43),
        " ".repeat(43),
        "é".repeat(43),
    ] {
        assert!(IssuerPkceVerifier::parse(invalid).is_err());
    }
    for invalid in ["A".repeat(42) + "B", "!".repeat(43), "A".repeat(44)] {
        assert!(pkce::challenge(&invalid).is_err());
    }
}

#[test]
fn authorization_is_bound_to_exact_context_client_and_closed_code_profile() {
    let (authority, client) = web();
    let request =
        IssuerAuthorizationRequest::new(authority.clone(), client.clone(), &input(client.client()))
            .unwrap();
    assert_eq!(request.authority(), &authority);
    assert_eq!(request.client(), &client);
    assert_eq!(
        request.pkce_challenge(),
        pkce::challenge(CHALLENGE).unwrap()
    );
    assert_eq!(
        format!("{request:?}"),
        "IssuerAuthorizationRequest([REDACTED])"
    );
    for wrong in [
        IssuerAuthorizationInput {
            response_type: "token",
            ..input(client.client())
        },
        IssuerAuthorizationInput {
            scope: "openid profile",
            ..input(client.client())
        },
        IssuerAuthorizationInput {
            code_challenge_method: "plain",
            ..input(client.client())
        },
        IssuerAuthorizationInput {
            code_challenge_method: "s256",
            ..input(client.client())
        },
        IssuerAuthorizationInput {
            client: Uuid::new_v4(),
            ..input(client.client())
        },
        IssuerAuthorizationInput {
            redirect_uri: "https://app.example/other",
            ..input(client.client())
        },
        IssuerAuthorizationInput {
            state: "",
            ..input(client.client())
        },
        IssuerAuthorizationInput {
            nonce: "bad\nnonce",
            ..input(client.client())
        },
    ] {
        assert!(
            IssuerAuthorizationRequest::new(authority.clone(), client.clone(), &wrong).is_err()
        );
    }
    let oversized = "x".repeat(1025);
    assert!(
        IssuerAuthorizationRequest::new(
            authority.clone(),
            client.clone(),
            &IssuerAuthorizationInput {
                nonce: &oversized,
                ..input(client.client())
            }
        )
        .is_err()
    );
    let other = IssuerAuthority::new(Uuid::new_v4(), authority.issuer()).unwrap();
    assert!(
        IssuerAuthorizationRequest::new(other, client.clone(), &input(client.client())).is_err()
    );
}

#[test]
fn fixed_callback_queries_cannot_duplicate_response_authority_fields() {
    let (authority, initial) = web();
    for query in [
        "code=stored",
        "%63ode=stored",
        "State=stored",
        "iss=stored",
        "error=stored",
        "id_token=stored",
    ] {
        let redirect = format!("https://app.example/cb?{query}");
        let client =
            IssuerClientRegistration::public(authority.realm(), initial.client(), &[&redirect])
                .unwrap();
        let request = IssuerAuthorizationInput {
            redirect_uri: &redirect,
            ..input(client.client())
        };
        assert!(IssuerAuthorizationRequest::new(authority.clone(), client, &request).is_err());
    }
}

#[test]
fn response_preserves_original_fixed_query_and_native_default_port_spelling() {
    let (authority, initial) = web();
    let code = Secret::generate().unwrap();
    for redirect in [
        "https://app.example/cb?mode=web%2fcontrol",
        "http://127.0.0.1:80/cb",
        "http://[::1]:80/cb",
    ] {
        let client = if redirect.starts_with("https") {
            IssuerClientRegistration::public(authority.realm(), initial.client(), &[redirect])
                .unwrap()
        } else {
            IssuerClientRegistration::public_native_loopback(
                authority.realm(),
                initial.client(),
                &[redirect],
            )
            .unwrap()
        };
        let data = IssuerAuthorizationDestination {
            client,
            redirect_uri: redirect.to_owned(),
            state: "original&state".to_owned(),
            expires_at_us: 1,
        };
        let returned = response::destination(&authority, data, Some(&code)).unwrap();
        assert!(returned.url().starts_with(redirect));
        let url = url::Url::parse(returned.url()).unwrap();
        let pairs: Vec<_> = url.query_pairs().collect();
        assert!(
            pairs.iter().find(|(k, _)| k == "code").unwrap().1 == code.expose(),
            "code binding"
        );
        assert_eq!(
            pairs.iter().find(|(k, _)| k == "state").unwrap().1,
            "original&state"
        );
        assert_eq!(
            pairs.iter().find(|(k, _)| k == "iss").unwrap().1,
            authority.issuer()
        );
        assert_eq!(
            format!("{returned:?}"),
            "IssuerAuthorizationReturn([REDACTED])"
        );
    }
}

#[test]
fn issuer_identity_is_trusted_https_context_without_request_overrides() {
    for value in [
        "http://issuer.example",
        "https://user@issuer.example",
        "https://issuer.example?q=1",
        "https://issuer.example#fragment",
        "https://issuer.example/a/../issuer",
        "https://ISSUER.example",
    ] {
        assert!(IssuerAuthority::new(Uuid::new_v4(), value).is_err());
    }
    assert!(IssuerAuthority::new(Uuid::nil(), "https://issuer.example").is_err());
    assert!(IssuerAuthority::new(Uuid::new_v4(), "https://issuer.example/realm").is_ok());
}
