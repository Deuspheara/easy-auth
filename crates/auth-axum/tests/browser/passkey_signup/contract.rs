use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn signup_contract_is_opt_in_concrete_and_preserves_prior_components(pool: PgPool) {
    let (app, auth, store) = app(pool).await;
    let normal = easy_auth_axum::router(auth.clone(), BrowserConfig::new(ORIGIN, false).unwrap());
    assert_eq!(
        normal
            .oneshot(post(
                START,
                r#"{"display_name":"Person"}"#,
                None,
                Some(ORIGIN)
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let spec = serde_json::to_value(passkey_signup_openapi()).unwrap();
    let prior = serde_json::to_value(easy_auth_axum::passkey_authentication_openapi()).unwrap();
    for (name, schema) in prior["components"]["schemas"].as_object().unwrap() {
        assert_eq!(
            &spec["components"]["schemas"][name], schema,
            "existing schema {name} changed"
        );
    }
    assert_eq!(
        spec["paths"][REGISTRATION]["post"]["requestBody"]["content"]["application/json"]["schema"]
            ["$ref"],
        "#/components/schemas/PasskeySignupRegistrationInput"
    );
    assert_eq!(
        spec["paths"][FINISH]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/PasskeySignupFinishInput"
    );
    let published: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/architecture/openapi-passkey-signup.json"
    ))
    .unwrap();
    assert_eq!(spec, published);
    let live = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json(live).await, spec);
    let service = Arc::new(PasskeyService::new(ORIGIN, "Example").unwrap());
    let enrollment = Arc::new(PasskeyEnrollment::new(
        auth.realm(),
        service.clone(),
        store.clone(),
    ));
    let sign_in = Arc::new(PasskeySignIn::new(auth.realm(), service, store.clone()));
    for (realm, origin) in [
        (Uuid::new_v4(), ORIGIN),
        (auth.realm(), "https://other.example"),
    ] {
        let signup = Arc::new(PasskeySignup::new(
            realm,
            Arc::new(PasskeyService::new(origin, "Example").unwrap()),
            store.clone(),
        ));
        assert!(
            experimental_passkey_signup_router(
                auth.clone(),
                BrowserConfig::new(ORIGIN, false).unwrap(),
                enrollment.clone(),
                sign_in.clone(),
                signup
            )
            .is_err()
        );
    }
}
