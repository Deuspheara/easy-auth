use super::*;
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn invalid_registration_challenge_origin_rp_or_uv_cannot_advance_signup(pool: PgPool) {
    for scenario in ["challenge", "origin", "rp", "uv"] {
        let mut f = Signup::new(pool.clone()).await;
        let pending = f.flow.begin("Person", &f.browser, SOURCE).await.unwrap();
        let client = software_creation(pending.options);
        let mut good = f
            .token
            .perform_register(ORIGIN.parse().unwrap(), client.public_key.clone(), 120_000)
            .unwrap();
        let mut options = client.public_key;
        let mut origin = ORIGIN;
        match scenario {
            "challenge" => options.challenge = vec![9; 32].into(),
            "origin" => origin = "https://other.example.com",
            "rp" => options.rp.id = "other.example.com".to_owned(),
            _ => (),
        }
        let (mut token, _) = SoftToken::new(true).unwrap();
        let mut bad = token
            .perform_register(origin.parse().unwrap(), options, 120_000)
            .unwrap();
        if scenario == "uv" {
            (good, bad) = without_uv(bad);
        }

        assert!(
            matches!(
                f.flow
                    .finish_registration(&f.browser, SOURCE, pending.transaction, &bad)
                    .await,
                Err(Error::Unauthorized)
            ),
            "{scenario}"
        );
        assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
        assert!(
            f.flow
                .finish_registration(&f.browser, SOURCE, pending.transaction, &good)
                .await
                .is_ok()
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_assertion_signature_owner_or_envelope_never_creates_an_account(pool: PgPool) {
    let mut f = Signup::new(pool).await;
    let (id, good) = f.assertion().await;
    for scenario in ["signature", "owner", "id", "oversize"] {
        let mut bad = good.clone();
        match scenario {
            "signature" => bad.response.signature = vec![0; 64].into(),
            "owner" => bad.response.user_handle = Some(Uuid::new_v4().as_bytes().to_vec().into()),
            "id" => bad.id = "AQ".to_owned(),
            _ => bad.response.client_data_json = vec![0; 16385].into(),
        }
        assert!(
            matches!(
                f.flow.finish(&f.browser, SOURCE, id, &bad).await,
                Err(Error::Unauthorized)
            ),
            "{scenario}"
        );
        assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
    }
    assert!(f.flow.finish(&f.browser, SOURCE, id, &good).await.is_ok());
}

// Same unsigned attestation is accepted with UV and rejected with only UV cleared.
fn without_uv(
    mut bad: PasskeyRegistrationResponse,
) -> (PasskeyRegistrationResponse, PasskeyRegistrationResponse) {
    use serde_cbor_2::Value;
    let mut object: Value =
        serde_cbor_2::from_slice(bad.response.attestation_object.as_slice()).unwrap();
    let Value::Map(ref mut map) = object else {
        panic!("attestation map")
    };
    map.insert(Value::Text("fmt".into()), Value::Text("none".into()));
    map.insert(
        Value::Text("attStmt".into()),
        Value::Map(Default::default()),
    );
    let mut good = bad.clone();
    good.response.attestation_object = serde_cbor_2::to_vec(&object).unwrap().into();
    let Value::Map(ref mut map) = object else {
        unreachable!()
    };
    let Value::Bytes(data) = map.get_mut(&Value::Text("authData".into())).unwrap() else {
        panic!("authenticator data")
    };
    data[32] &= !4;
    bad.response.attestation_object = serde_cbor_2::to_vec(&object).unwrap().into();
    (good, bad)
}
