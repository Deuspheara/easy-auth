use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn recovery_configuration_contract_is_explicit_closed_and_preserves_prior_schemas(
    pool: PgPool,
) {
    let f = Fixture::new(pool, false).await;
    let normal = easy_auth_axum::router(f.auth.clone(), BrowserConfig::new(ORIGIN, false).unwrap());
    for older in [normal, f.app.clone()] {
        for path in [PREPARE, CONFIRM] {
            assert_eq!(
                send(&older, &f, path, &json!({})).await.status(),
                StatusCode::NOT_FOUND
            );
        }
    }
    let spec = serde_json::to_value(easy_auth_axum::passkey_recovery_setup_openapi()).unwrap();
    let prior = serde_json::to_value(easy_auth_axum::passkey_management_openapi()).unwrap();
    for (name, schema) in prior["components"]["schemas"].as_object().unwrap() {
        assert!(
            spec["components"]["schemas"][name] == *schema,
            "prior schema preserved: {name}"
        );
    }
    for (path, value) in prior["paths"].as_object().unwrap() {
        assert!(
            spec["paths"][path] == *value,
            "prior route preserved: {path}"
        );
    }
    for (path, name) in [
        (PREPARE, "PrepareRecoveryCodeInput"),
        (CONFIRM, "ConfirmRecoveryCodeInput"),
    ] {
        assert_eq!(
            spec["paths"][path]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            format!("#/components/schemas/{name}")
        );
        assert_eq!(
            spec["components"]["schemas"][name]["additionalProperties"],
            false
        );
    }
    assert_eq!(
        spec["components"]["schemas"]["PreparedRecoveryCodeResponse"]["properties"]["code"]["maxLength"],
        43
    );
    let published: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../docs/architecture/openapi-passkey-recovery-setup.json"
    ))
    .unwrap();
    assert!(spec == published);
    let app = app(&f, f.auth.clone());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(super::super::json(response).await == spec);
    for (realm, origin) in [
        (Uuid::new_v4(), ORIGIN),
        (f.auth.realm(), "https://other.example"),
    ] {
        let service = Arc::new(PasskeyService::new(origin, "Example").unwrap());
        assert!(
            easy_auth_axum::experimental_passkey_recovery_setup_router(
                f.auth.clone(),
                BrowserConfig::new(ORIGIN, false).unwrap(),
                f.enrollment.clone(),
                f.sign_in.clone(),
                Arc::new(PasskeySignup::new(
                    f.auth.realm(),
                    f.service.clone(),
                    f.store.clone()
                )),
                Arc::new(PasskeyManagement::new(
                    f.auth.realm(),
                    f.service.clone(),
                    f.store.clone()
                )),
                Arc::new(PasskeyRecoverySetup::new(realm, service, f.store.clone())),
            )
            .is_err()
        );
    }
}
