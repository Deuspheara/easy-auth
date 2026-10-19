use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn management_contract_is_explicit_concrete_complete_and_startup_bound(pool: PgPool) {
    let f = Fixture::new(pool, false).await;
    let normal = easy_auth_axum::router(f.auth.clone(), BrowserConfig::new(ORIGIN, false).unwrap());
    let signup = easy_auth_axum::experimental_passkey_signup_router(
        f.auth.clone(),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        f.enrollment.clone(),
        f.sign_in.clone(),
        Arc::new(PasskeySignup::new(
            f.auth.realm(),
            f.service.clone(),
            f.store.clone(),
        )),
    )
    .unwrap();
    for app in [normal, signup] {
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri(INVENTORY)
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        for path in [RENAME, REMOVE] {
            assert_eq!(
                app.clone()
                    .oneshot(post(path, "{}", None, Some(ORIGIN)))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
    }
    let spec = serde_json::to_value(easy_auth_axum::passkey_management_openapi()).unwrap();
    let prior = serde_json::to_value(easy_auth_axum::passkey_signup_openapi()).unwrap();
    for (name, schema) in prior["components"]["schemas"].as_object().unwrap() {
        assert_eq!(&spec["components"]["schemas"][name], schema);
    }
    for (path, value) in prior["paths"].as_object().unwrap() {
        assert_eq!(&spec["paths"][path], value);
    }
    for (path, name) in [
        (RENAME, "RenamePasskeyInput"),
        (REMOVE, "RemovePasskeyInput"),
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
        spec["components"]["schemas"]["PasskeyInventoryResponse"]["properties"]["passkeys"]["maxItems"],
        10
    );
    let published: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/architecture/openapi-passkey-management.json"
    ))
    .unwrap();
    assert_eq!(spec, published);
    assert_eq!(json(f.get("/openapi.json", &f.cookie()).await).await, spec);
    for (realm, origin) in [
        (Uuid::new_v4(), ORIGIN),
        (f.auth.realm(), "https://other.example"),
    ] {
        let flow = Arc::new(PasskeyManagement::new(
            realm,
            Arc::new(PasskeyService::new(origin, "Example").unwrap()),
            f.store.clone(),
        ));
        assert!(
            experimental_passkey_management_router(
                f.auth.clone(),
                BrowserConfig::new(ORIGIN, false).unwrap(),
                f.enrollment.clone(),
                f.sign_in.clone(),
                Arc::new(PasskeySignup::new(
                    f.auth.realm(),
                    f.service.clone(),
                    f.store.clone()
                )),
                flow
            )
            .is_err()
        );
    }
}
