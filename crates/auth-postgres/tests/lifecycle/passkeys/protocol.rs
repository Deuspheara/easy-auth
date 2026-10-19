use super::*;
use auth_core::Error;
use serde_cbor_2::Value;

#[sqlx::test(migrations = "./migrations")]
async fn rejects_contradictory_or_oversized_public_envelopes(pool: PgPool) {
    let mut f = Fixture::new(pool).await;
    for scenario in ["type", "raw-id", "id", "oversize"] {
        let (id, good, mut token) = f.begin_with_token().await;
        let mut bad = good.clone();
        match scenario {
            "type" => bad.type_ = "password".to_owned(),
            "raw-id" => bad.raw_id = vec![0].into(),
            "id" => bad.id = "AQ".to_owned(),
            "oversize" => bad.response.client_data_json = vec![0; 16385].into(),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                f.enrollment
                    .finish(&f.session, &f.browser, SOURCE, id, &bad)
                    .await,
                Err(Error::Unauthorized)
            ),
            "{scenario}"
        );
        assert!(
            f.enrollment
                .finish(&f.session, &f.browser, SOURCE, id, &good)
                .await
                .is_ok(),
            "{scenario} positive control"
        );
        f.session = f.sign_in_with_key(&mut token).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn unsigned_attestation_still_requires_user_presence(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (id, mut good) = f.begin().await;
    let mut object: Value =
        serde_cbor_2::from_slice(good.response.attestation_object.as_slice()).unwrap();
    let Value::Map(ref mut map) = object else {
        panic!("attestation map")
    };
    // Standard 'none' attestation has no signature; the positive control must
    // still require UP, so signature failure cannot explain this rejection.
    map.insert(
        Value::Text("fmt".to_owned()),
        Value::Text("none".to_owned()),
    );
    map.insert(
        Value::Text("attStmt".to_owned()),
        Value::Map(Default::default()),
    );
    good.response.attestation_object = serde_cbor_2::to_vec(&object).unwrap().into();
    let Value::Map(ref mut map) = object else {
        unreachable!()
    };
    let Value::Bytes(data) = map.get_mut(&Value::Text("authData".to_owned())).unwrap() else {
        panic!("authenticator data")
    };
    data[32] &= !1;
    let mut bad = good.clone();
    bad.response.attestation_object = serde_cbor_2::to_vec(&object).unwrap().into();
    assert!(matches!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &bad)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &good)
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_wrong_challenge_origin_rp_and_missing_verification(pool: PgPool) {
    let mut f = Fixture::new(pool).await;
    for scenario in ["challenge", "origin", "rp", "uv"] {
        let pending = f
            .enrollment
            .begin(&f.session, &f.browser, SOURCE, "key")
            .await
            .unwrap();
        let (mut token, _) = SoftToken::new(true).unwrap();
        let good = token
            .perform_register(
                ORIGIN.parse().unwrap(),
                pending.options.public_key.clone(),
                120_000,
            )
            .unwrap();
        let mut options = pending.options;
        let bad = match scenario {
            "challenge" => {
                options.public_key.challenge = vec![7; 32].into();
                register(options, ORIGIN, true)
            }
            "origin" => register(options, "https://sub.login.example.com", true),
            "rp" => {
                options.public_key.rp.id = "example.com".to_owned();
                register(options, ORIGIN, true)
            }
            "uv" => {
                let mut value = serde_json::to_value(options).unwrap();
                value["publicKey"]["authenticatorSelection"]["userVerification"] =
                    serde_json::json!("discouraged");
                register(serde_json::from_value(value).unwrap(), ORIGIN, false)
            }
            _ => unreachable!(),
        };
        assert!(
            matches!(
                f.enrollment
                    .finish(&f.session, &f.browser, SOURCE, pending.transaction, &bad)
                    .await,
                Err(Error::Unauthorized)
            ),
            "{scenario}"
        );
        assert!(
            f.enrollment
                .finish(&f.session, &f.browser, SOURCE, pending.transaction, &good)
                .await
                .is_ok(),
            "{scenario} positive control"
        );
        f.session = f.sign_in_with_key(&mut token).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn verifies_packed_attestation_signature_and_rejects_tampering(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let pending = f
        .enrollment
        .begin(&f.session, &f.browser, SOURCE, "key")
        .await
        .unwrap();
    let good = register(pending.options, ORIGIN, true);
    let mut object: Value =
        serde_cbor_2::from_slice(good.response.attestation_object.as_slice()).unwrap();
    let Value::Map(ref mut object) = object else {
        panic!("attestation map")
    };
    assert_eq!(
        object.get(&Value::Text("fmt".to_owned())),
        Some(&Value::Text("packed".to_owned()))
    );
    let Value::Map(statement) = object.get_mut(&Value::Text("attStmt".to_owned())).unwrap() else {
        panic!("signed statement")
    };
    let Value::Bytes(signature) = statement.get_mut(&Value::Text("sig".to_owned())).unwrap() else {
        panic!("signature bytes")
    };
    signature[0] ^= 1;
    let mut bad = good.clone();
    bad.response.attestation_object = serde_cbor_2::to_vec(&object).unwrap().into();
    assert!(matches!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, pending.transaction, &bad)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, pending.transaction, &good)
            .await
            .is_ok()
    );
}
