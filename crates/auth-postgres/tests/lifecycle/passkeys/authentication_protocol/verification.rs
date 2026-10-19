use super::*;
use auth_core::Error;
use serde_json::json;

#[test]
fn signed_assertion_updates_counter_and_refuses_a_cloned_counter() {
    let mut p = Protocol::new();
    // Test-only in-memory snapshot simulates a cloned nonresident token. Never write it to disk/logs.
    let snapshot = p.token.to_cbor().unwrap();
    let (options, state) = p.begin();
    let public = serde_json::to_value(&options).unwrap();
    assert_eq!(public["publicKey"]["userVerification"], "required");
    assert_eq!(public["publicKey"]["rpId"], "login.example.com");
    assert_eq!(
        public["publicKey"]["allowCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(public.get("state").is_none());
    let response = p.sign(options);
    let proof = p.verify(&response, Protocol::restore(&state)).unwrap();
    assert_eq!(proof.user_id(), p.owner);
    assert_eq!(proof.realm(), p.realm);
    assert_eq!(proof.credential_id(), p.id);
    assert_eq!(proof.expected_credential_for_database(), p.encoded);
    let updated: serde_json::Value =
        serde_json::from_slice(proof.updated_credential_for_database()).unwrap();
    assert_eq!(updated["cred"]["counter"], 1);
    assert_eq!(updated["cred"]["backup_eligible"], false);
    assert_eq!(
        format!("{proof:?}"),
        "VerifiedPasskeyAuthentication([REDACTED])"
    );
    p.encoded = proof.updated_credential_for_database().to_vec();
    // Even a valid proof from an old state cannot overwrite a newer stored snapshot.
    assert!(matches!(
        p.verify(&response, state),
        Err(Error::Unauthorized)
    ));
    let (options, state) = p.begin();
    let mut cloned = SoftToken::from_cbor(&snapshot).unwrap();
    let response = cloned
        .perform_auth(ORIGIN.parse().unwrap(), options.public_key, 120_000)
        .unwrap();
    assert!(matches!(
        p.verify(&response, state),
        Err(Error::Unauthorized)
    ));
    // The real token advances and still works: no permanent account lockout was introduced.
    let (options, state) = p.begin();
    let response = p.sign(options);
    let proof = p.verify(&response, state).unwrap();
    let updated: serde_json::Value =
        serde_json::from_slice(proof.updated_credential_for_database()).unwrap();
    assert_eq!(updated["cred"]["counter"], 2);
}

#[test]
fn rejects_signed_wrong_challenge_rp_origin_and_missing_uv_with_valid_controls() {
    let mut p = Protocol::new();
    for variant in ["challenge", "rp", "origin", "uv", "signature"] {
        let (mut options, state) = p.begin();
        let mut origin = ORIGIN;
        match variant {
            "challenge" => options.public_key.challenge = vec![9; 32].into(),
            "rp" => options.public_key.rp_id = "other.example.com".to_owned(),
            "origin" => origin = "https://sub.login.example.com",
            "uv" => {
                options.public_key.user_verification =
                    serde_json::from_value(json!("discouraged")).unwrap()
            }
            _ => {}
        }
        let mut response = p
            .token
            .perform_auth(origin.parse().unwrap(), options.public_key, 120_000)
            .unwrap();
        if variant == "signature" {
            let mut signature = response.response.signature.to_vec();
            let last = signature.len() - 1;
            signature[last] ^= 1;
            response.response.signature = signature.into();
        }
        assert!(
            matches!(p.verify(&response, state), Err(Error::Unauthorized)),
            "{variant}"
        );
        let (options, state) = p.begin();
        let response = p.sign(options);
        assert!(p.verify(&response, state).is_ok(), "control for {variant}");
    }
}

#[test]
fn backup_eligibility_cannot_change_even_with_a_valid_signature() {
    let mut p = Protocol::new();
    // Model a trusted previously backup-eligible credential; this token signs BE=false.
    // Both modes must reject that contradiction; the signature itself remains valid.
    let mut stored: serde_json::Value = serde_json::from_slice(&p.encoded).unwrap();
    stored["cred"]["backup_eligible"] = json!(true);
    let previous = p.encoded.clone();
    p.encoded = serde_json::to_vec(&stored).unwrap();
    let (options, state) = p.begin();
    let response = p.sign(options);
    assert!(matches!(
        p.verify(&response, state),
        Err(Error::Unauthorized)
    ));
    p.encoded = previous;
    let (options, state) = p.begin();
    let response = p.sign(options);
    assert!(p.verify(&response, state).is_ok());
}
