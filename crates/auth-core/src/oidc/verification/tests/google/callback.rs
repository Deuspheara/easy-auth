use crate::*;

const ISSUER: &str = "https://accounts.google.com";

fn query(state: &Secret, outcome: &str) -> String {
    format!(
        "state={}&iss=https%3A%2F%2Faccounts.google.com&{outcome}",
        state.expose()
    )
}

#[test]
fn google_callback_retains_only_actual_state_issuer_and_redacted_code() {
    let state = Secret::generate().unwrap();
    let input = query(
        &state,
        "code=4%2Fexample%2Bcode&scope=openid+email&authuser=0&hd=example.com&prompt=consent&session_state=opaque",
    );
    let response = GoogleAuthorizationResponse::parse(&input).unwrap();
    assert_eq!(response.state().verifier(), state.verifier());
    assert_eq!(response.issuer(), ISSUER);
    let debug = format!("{response:?}");
    for private in [state.expose(), "example+code", "example.com", "opaque"] {
        assert!(!debug.contains(private));
    }
    assert!(matches!(
        response.into_outcome(),
        GoogleAuthorizationOutcome::Code(_)
    ));
}

#[test]
fn google_callback_denial_and_provider_failure_discard_foreign_details() {
    let state = Secret::generate().unwrap();
    for error in [
        "access_denied",
        "server_error",
        "temporarily_unavailable",
        "new_provider_error",
    ] {
        let input = query(
            &state,
            &format!(
                "error={error}&error_description=private-foreign-detail&error_uri=https%3A%2F%2Fprivate.example%2Fdetail"
            ),
        );
        let response = GoogleAuthorizationResponse::parse(&input).unwrap();
        assert_eq!(response.state().verifier(), state.verifier());
        assert_eq!(response.issuer(), ISSUER);
        let debug = format!("{response:?}");
        for private in [
            state.expose(),
            "private-foreign-detail",
            "private.example",
            "new_provider_error",
        ] {
            assert!(!debug.contains(private));
        }
        match response.into_outcome() {
            GoogleAuthorizationOutcome::Denied => assert_eq!(error, "access_denied"),
            GoogleAuthorizationOutcome::ProviderFailure => assert_ne!(error, "access_denied"),
            GoogleAuthorizationOutcome::Code(_) => panic!("error cannot become an exchange code"),
        }
    }
}

#[test]
fn google_callback_requires_exact_issuer_on_success_and_failure() {
    let state = Secret::generate().unwrap();
    for outcome in ["code=valid", "error=access_denied", "error=server_error"] {
        assert!(matches!(
            GoogleAuthorizationResponse::parse(&format!("state={}&{outcome}", state.expose())),
            Err(Error::Unauthorized)
        ));
        for issuer in [
            "",
            "accounts.google.com",
            "https://accounts.google.com/",
            "https://ACCOUNTS.google.com",
            "https://attacker.example",
            "https://accounts.google.com@attacker.example",
        ] {
            let input = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("state", state.expose())
                .append_pair("iss", issuer)
                .finish();
            assert!(matches!(
                GoogleAuthorizationResponse::parse(&format!("{input}&{outcome}")),
                Err(Error::Unauthorized)
            ));
        }
    }
}

#[test]
fn google_callback_rejects_ambiguity_duplicate_decoded_members_and_uploads() {
    let state = Secret::generate().unwrap();
    for outcome in [
        "",
        "code=",
        "error=",
        "code=a&error=access_denied",
        "code=a&code=b",
        "code=a&%63ode=b",
        "code=a&iss=https%3A%2F%2Faccounts.google.com",
        "code=a&%73tate=invalid",
        "code=a&scope=one&scope=two",
        "code=a&error_description=detail",
        "code=a&error_uri=https://example.com",
        "code=a&id_token=upload",
        "code=a&access_token=upload",
        "code=a&redirect_uri=https://attacker.example",
        "code=a&client_id=other",
        "code=a&unknown=ignored",
        "error=access_denied&error=server_error",
    ] {
        assert!(matches!(
            GoogleAuthorizationResponse::parse(&query(&state, outcome)),
            Err(Error::Unauthorized)
        ));
    }
    assert!(matches!(
        GoogleAuthorizationResponse::parse("iss=https://accounts.google.com&code=a"),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        GoogleAuthorizationResponse::parse("state=invalid&iss=https://accounts.google.com&code=a"),
        Err(Error::Unauthorized)
    ));
}

#[test]
fn google_callback_rejects_malformed_encoding_controls_and_fragments() {
    let state = Secret::generate().unwrap();
    for outcome in [
        "code=%",
        "code=%2",
        "code=%GG",
        "code=%FF",
        "code=%00",
        "code=%0d%0a",
        "code=%C3%A9",
        "code=a#fragment",
        "code=a&scope=%00",
        "code=a&prompt=%FF",
        "code=a&error_description=%00",
        "error=%FF",
        "error=access_denied&error_uri=%GG",
    ] {
        assert!(matches!(
            GoogleAuthorizationResponse::parse(&query(&state, outcome)),
            Err(Error::Unauthorized)
        ));
    }
    let valid = query(&state, "code=a");
    for input in [
        format!("?{valid}"),
        format!("https://app.example/callback?{valid}"),
    ] {
        assert!(matches!(
            GoogleAuthorizationResponse::parse(&input),
            Err(Error::Unauthorized)
        ));
    }
}

#[test]
fn google_callback_enforces_value_and_total_bounds_with_positive_controls() {
    let state = Secret::generate().unwrap();
    let accepted = query(&state, &format!("code={}", "a".repeat(2048)));
    assert!(GoogleAuthorizationResponse::parse(&accepted).is_ok());
    for field in [
        "code",
        "scope",
        "error_description",
        "error_uri",
        "authuser",
        "hd",
        "prompt",
        "session_state",
    ] {
        let outcome = if field == "code" {
            String::new()
        } else if field.starts_with("error_") {
            "error=server_error&".into()
        } else {
            "code=a&".into()
        };
        let input = query(&state, &format!("{outcome}{field}={}", "a".repeat(2049)));
        assert!(matches!(
            GoogleAuthorizationResponse::parse(&input),
            Err(Error::Unauthorized)
        ));
    }
    let input = query(
        &state,
        &format!(
            "code=a&scope={}&authuser={}&hd={}&prompt={}",
            "a".repeat(2048),
            "a".repeat(2048),
            "a".repeat(2048),
            "a".repeat(2048)
        ),
    );
    assert!(matches!(
        GoogleAuthorizationResponse::parse(&input),
        Err(Error::Unauthorized)
    ));
    assert!(GoogleAuthorizationResponse::parse(&query(&state, "code=valid")).is_ok());
}
