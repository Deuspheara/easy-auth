use super::*;
use serde_json::{Value, json};

#[test]
fn rejects_ambiguous_or_insecure_configuration() {
    for origin in [
        "http://login.example.com",
        "https://login.example.com/path",
        "https://login.example.com?query=1",
        "https://login.example.com#fragment",
        "https://user:password@login.example.com",
        "https://@login.example.com",
        "https://login.example.com.",
        "https://com",
        "https://127.0.0.1",
        "https://[::1]",
        " https://login.example.com",
        "https://login.example.com\n",
        "file:///login.example.com",
    ] {
        assert!(matches!(
            PasskeyService::new(origin, "Example"),
            Err(Error::InvalidInput)
        ));
    }
    for name in ["", "   ", "Invalid\nname", &"x".repeat(257)] {
        assert!(matches!(
            PasskeyService::new("https://login.example.com", name),
            Err(Error::InvalidInput)
        ));
    }
    assert!(PasskeyService::for_local_development("http://example.com", "Example").is_err());
    assert!(PasskeyService::new("http://localhost:3300", "Example").is_err());
    assert!(PasskeyService::for_local_development("http://localhost:3300", "Example").is_ok());
}

#[test]
fn options_require_verification_and_bind_opaque_owner_to_exact_rp() {
    let service = PasskeyService::new("https://login.example.com:8443", "Example").unwrap();
    let owner = Uuid::new_v4();
    let (options, state) = service
        .begin_registration(owner, "account label", &[vec![1, 2, 3]])
        .unwrap();
    let public = serde_json::to_value(options).unwrap();
    assert_eq!(public["publicKey"]["rp"]["id"], "login.example.com");
    assert_eq!(public["publicKey"]["user"]["name"], "account label");
    assert_eq!(
        public["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert!(public["publicKey"]["authenticatorSelection"]["authenticatorAttachment"].is_null());
    assert_eq!(public["publicKey"]["excludeCredentials"][0]["id"], "AQID");
    assert!(public.get("state").is_none());
    let stored: Value = serde_json::from_slice(&state.encode_for_database().unwrap()).unwrap();
    assert_eq!(stored["version"], 1);
    assert_eq!(stored["origin"], "https://login.example.com:8443/");
    assert!(stored.get("state").is_some());
    assert_eq!(
        format!("{state:?}"),
        "PrivatePasskeyRegistration([REDACTED])"
    );
}

#[test]
fn bounded_enrollment_and_server_state_round_trip() {
    let service = PasskeyService::new("https://login.example.com", "Example").unwrap();
    let owner = Uuid::new_v4();
    assert!(
        service
            .begin_registration(Uuid::nil(), "label", &[])
            .is_err()
    );
    for exclusions in [vec![vec![]], vec![vec![0; 1025]], vec![vec![1]; 10]] {
        assert!(
            service
                .begin_registration(owner, "label", &exclusions)
                .is_err()
        );
    }
    let (first, state) = service.begin_registration(owner, "label", &[]).unwrap();
    let (second, _) = service.begin_registration(owner, "label", &[]).unwrap();
    let first = serde_json::to_value(first).unwrap();
    let second = serde_json::to_value(second).unwrap();
    assert_ne!(
        first["publicKey"]["challenge"],
        second["publicKey"]["challenge"]
    );
    let encoded = state.encode_for_database().unwrap();
    let restored = PrivatePasskeyRegistration::decode_from_database(&encoded).unwrap();
    assert_eq!(encoded, restored.encode_for_database().unwrap());
    let mut future: Value = serde_json::from_slice(&encoded).unwrap();
    future["version"] = json!(2);
    for invalid in [
        serde_json::to_vec(&future).unwrap(),
        vec![0; 32769],
        b"{}".to_vec(),
    ] {
        assert!(matches!(
            PrivatePasskeyRegistration::decode_from_database(&invalid),
            Err(Error::Unavailable)
        ));
    }
}

#[test]
fn refuses_saved_state_after_origin_or_port_change_and_redacts_failure() {
    let original = PasskeyService::new("https://login.example.com", "Example").unwrap();
    let response: PasskeyRegistrationResponse = serde_json::from_value(json!({
        "id": "AQ", "rawId": "AQ", "type": "public-key",
        "response": {"attestationObject": "AA", "clientDataJSON": "e30"}
    }))
    .unwrap();
    for origin in [
        "https://login.example.com:8443",
        "https://sub.login.example.com",
        "https://other.example.com",
    ] {
        let (_, state) = original
            .begin_registration(Uuid::new_v4(), "label", &[])
            .unwrap();
        let changed = PasskeyService::new(origin, "Example").unwrap();
        assert!(matches!(
            changed.verify_registration(&response, state),
            Err(Error::Unauthorized)
        ));
    }
    let (_, state) = original
        .begin_registration(Uuid::new_v4(), "label", &[])
        .unwrap();
    let failure = original.verify_registration(&response, state).unwrap_err();
    assert!(matches!(failure, Error::Unauthorized));
    assert_eq!(failure.to_string(), "authentication required");
}
