use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn full_contract_is_opt_in_preserves_existing_schemas_and_checks_startup_binding(
    pool: PgPool,
) {
    let (app, auth, store) = app(pool).await;
    let normal = easy_auth_axum::router(auth.clone(), BrowserConfig::new(ORIGIN, false).unwrap());
    let response = normal
        .oneshot(post(
            START,
            r#"{"mode":"discoverable"}"#,
            None,
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let spec = serde_json::to_value(passkey_authentication_openapi()).unwrap();
    let enrollment = serde_json::to_value(easy_auth_axum::passkey_enrollment_openapi()).unwrap();
    for (name, schema) in enrollment["components"]["schemas"].as_object().unwrap() {
        assert_eq!(
            &spec["components"]["schemas"][name], schema,
            "existing schema {name} changed"
        );
    }
    assert_eq!(
        spec["paths"][FINISH]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/PasskeyAuthenticationFinishInput"
    );
    assert!(
        spec["components"]["schemas"]["PasskeyAuthenticationFinishInput"]["properties"]
            .get("credential")
            .is_some()
    );
    let published: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/architecture/openapi-passkeys.json"
    ))
    .unwrap();
    assert_eq!(spec, published);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let served: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(served, spec);
    let service = Arc::new(PasskeyService::new(ORIGIN, "Example").unwrap());
    let enrollment = Arc::new(PasskeyEnrollment::new(auth.realm(), service, store.clone()));
    for (realm, origin) in [
        (Uuid::new_v4(), ORIGIN),
        (auth.realm(), "https://other.example"),
    ] {
        let sign_in = Arc::new(PasskeySignIn::new(
            realm,
            Arc::new(PasskeyService::new(origin, "Example").unwrap()),
            store.clone(),
        ));
        assert!(
            experimental_passkey_router(
                auth.clone(),
                BrowserConfig::new(ORIGIN, false).unwrap(),
                enrollment.clone(),
                sign_in
            )
            .is_err()
        );
    }
}
