use super::*;
use auth_core::Error;
use serde_json::json;

#[test]
fn bound_state_rejects_another_owner_realm_rp_or_changed_origin() {
    let mut p = Protocol::new();
    let (options, state) = p.begin();
    let response = p.sign(options);
    for (realm, owner, rp) in [
        (Uuid::new_v4(), p.owner, p.service.rp_id()),
        (p.realm, Uuid::new_v4(), p.service.rp_id()),
        (p.realm, p.owner, "other.example.com"),
    ] {
        let stored = p.stored_as(realm, owner, rp, &p.encoded);
        assert!(matches!(
            p.service
                .verify_authentication(&response, Protocol::restore(&state), stored),
            Err(Error::Unauthorized)
        ));
    }
    for origin in [
        "https://login.example.com:8443",
        "https://sub.login.example.com",
    ] {
        let other = PasskeyService::new(origin, "Example").unwrap();
        assert!(matches!(
            other.verify_authentication(&response, Protocol::restore(&state), p.stored()),
            Err(Error::Unauthorized)
        ));
    }
    let mut changed = response.clone();
    changed.response.user_handle = Some(Uuid::new_v4().as_bytes().to_vec().into());
    assert!(matches!(
        p.verify(&changed, Protocol::restore(&state)),
        Err(Error::Unauthorized)
    ));
    assert!(p.verify(&response, state).is_ok());
}

#[test]
fn discoverable_proof_requires_a_handle_owned_by_the_trusted_credential() {
    let mut p = Protocol::new();
    let (mut options, state) = p
        .service
        .begin_discoverable_authentication(p.realm)
        .unwrap();
    let public = serde_json::to_value(&options).unwrap();
    assert_eq!(public["mediation"], "conditional");
    assert_eq!(public["publicKey"]["userVerification"], "required");
    assert!(
        public["publicKey"]["allowCredentials"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // The software token lacks residence/discovery. Supply its known key only to this
    // test signer; server state stays discoverable. This is protocol proof, not browser UX evidence.
    options.public_key.allow_credentials = p.begin().0.public_key.allow_credentials;
    let mut response = p.sign(options);
    for handle in [
        None,
        Some(vec![1]),
        Some(Uuid::new_v4().as_bytes().to_vec()),
    ] {
        response.response.user_handle = handle.map(Into::into);
        assert!(matches!(
            p.verify(&response, Protocol::restore(&state)),
            Err(Error::Unauthorized)
        ));
    }
    response.response.user_handle = Some(p.owner.as_bytes().to_vec().into());
    assert!(p.verify(&response, state).is_ok());
}

#[test]
fn private_state_and_envelope_are_bounded_versioned_and_redacted() {
    let mut p = Protocol::new();
    let (options, state) = p.begin();
    let encoded = state.encode_for_database().unwrap();
    assert_eq!(
        encoded,
        Protocol::restore(&state).encode_for_database().unwrap()
    );
    assert_eq!(
        format!("{state:?}"),
        "PrivatePasskeyAuthentication([REDACTED])"
    );
    assert_eq!(format!("{:?}", p.stored()), "StoredPasskey([REDACTED])");
    let mut unknown: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    unknown["version"] = json!(2);
    for invalid in [
        serde_json::to_vec(&unknown).unwrap(),
        vec![0; 131_073],
        b"{}".to_vec(),
    ] {
        assert!(matches!(
            PrivatePasskeyAuthentication::decode_from_database(&invalid),
            Err(Error::Unavailable)
        ));
    }
    let response = p.sign(options);
    for variant in ["type", "id", "raw", "oversize"] {
        let mut changed = response.clone();
        match variant {
            "type" => changed.type_ = "other".to_owned(),
            "id" => changed.id.push('='),
            "raw" => changed.raw_id = vec![1].into(),
            _ => changed.response.signature = vec![0; 16_385].into(),
        }
        assert!(matches!(
            p.verify(&changed, Protocol::restore(&state)),
            Err(Error::Unauthorized)
        ));
    }
    assert!(p.verify(&response, state).is_ok());
    assert!(
        p.service
            .begin_account_authentication(p.realm, p.owner, &[])
            .is_err()
    );
    assert!(
        p.service
            .begin_account_authentication(Uuid::new_v4(), p.owner, &[p.stored()])
            .is_err()
    );
    assert!(
        p.service
            .begin_discoverable_authentication(Uuid::nil())
            .is_err()
    );
    assert!(
        StoredPasskey::decode_from_database(p.realm, p.owner, p.service.rp_id(), &[1], &p.encoded)
            .is_err()
    );
}
