use super::setup::*;

fn form(state: &Secret, members: &[(&str, &str)]) -> String {
    let mut fields = url::form_urlencoded::Serializer::new(String::new());
    fields.append_pair("state", state.expose());
    for (key, value) in members {
        fields.append_pair(key, value);
    }
    fields.finish()
}

#[test]
fn first_consent_profile_is_optional_unsigned_presentation_and_debug_is_redacted() {
    let state = Secret::generate().unwrap();
    for user in [
        None,
        Some(
            r#"{"name":{"firstName":"<b>Owned</b>","lastName":"Example"},"email":"unsigned@example.test"}"#,
        ),
    ] {
        let mut fields = vec![
            ("code", "owned-code"),
            ("id_token", "ignored-frontchannel-token"),
        ];
        if let Some(user) = user {
            fields.push(("user", user));
        }
        let response = AppleAuthorizationResponse::parse(&form(&state, &fields)).unwrap();
        assert_eq!(response.state().verifier(), state.verifier());
        let AppleAuthorizationOutcome::Code {
            initial_profile, ..
        } = response.outcome()
        else {
            panic!("expected untrusted code outcome");
        };
        assert_eq!(initial_profile.is_some(), user.is_some());
        if let Some(profile) = initial_profile {
            assert_eq!(profile.first_name(), Some("<b>Owned</b>"));
            assert_eq!(profile.last_name(), Some("Example"));
        }
        let debug = format!("{response:?}");
        for private in [
            state.expose(),
            "owned-code",
            "ignored-frontchannel-token",
            "unsigned@example.test",
            "Owned",
        ] {
            assert!(!debug.contains(private));
        }
    }
}

#[test]
fn malformed_duplicate_contradictory_and_oversized_returns_fail_closed() {
    let state = Secret::generate().unwrap();
    for members in [
        vec![("state", state.expose()), ("code", "code")],
        vec![("code", "one"), ("code", "two")],
        vec![("code", "code"), ("error", "user_cancelled_authorize")],
        vec![("code", "code"), ("iss", "https://foreign.example")],
        vec![("id_token", "unsolicited-token")],
        vec![("code", "code"), ("unknown", "ignored?")],
        vec![("code", "code"), ("user", "null")],
        vec![
            ("code", "code"),
            ("user", r#"{"name":{"firstName":"one","firstName":"two"}}"#),
        ],
        vec![
            ("error", "user_cancelled_authorize"),
            ("id_token", "code-result"),
        ],
        vec![
            ("code", "code"),
            ("user", r#"{"name":{"firstName":"line\nbreak"}}"#),
        ],
    ] {
        assert!(matches!(
            AppleAuthorizationResponse::parse(&form(&state, &members)),
            Err(Error::Unauthorized)
        ));
    }
    for bad in ["%", "%FF", "#fragment", "?code=x"] {
        assert!(
            AppleAuthorizationResponse::parse(&format!(
                "{}&{bad}",
                form(&state, &[("code", "code")])
            ))
            .is_err()
        );
    }
    assert!(
        AppleAuthorizationResponse::parse(&form(&state, &[("code", &"x".repeat(2049))])).is_err()
    );
    let encoded_duplicate = format!(
        "{}&%73tate={}",
        form(&state, &[("code", "code")]),
        state.expose()
    );
    assert!(AppleAuthorizationResponse::parse(&encoded_duplicate).is_err());
    assert!(AppleAuthorizationResponse::parse(&"x".repeat(32769)).is_err());
}
