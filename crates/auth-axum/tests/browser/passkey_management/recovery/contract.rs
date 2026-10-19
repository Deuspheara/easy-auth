use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn recovery_http_is_opt_in_with_closed_full_contract_and_preserves_all_prior_schemas(
    pool: PgPool,
) {
    let r = Recovery::new(pool, true).await;
    let prior = serde_json::to_value(easy_auth_axum::passkey_recovery_setup_openapi()).unwrap();
    let spec = serde_json::to_value(easy_auth_axum::passkey_recovery_openapi()).unwrap();
    for (name, schema) in prior["components"]["schemas"].as_object().unwrap() {
        assert!(
            spec["components"]["schemas"][name] == *schema,
            "prior schema preserved: {name}"
        );
    }
    for (path, operation) in prior["paths"].as_object().unwrap() {
        assert!(
            spec["paths"][path] == *operation,
            "prior operation preserved: {path}"
        );
    }
    let published: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../docs/architecture/openapi-passkey-recovery.json"
    ))
    .unwrap();
    assert!(published == spec);
    let live = r
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(json(live).await == spec);
    let old = easy_auth_axum::experimental_passkey_recovery_setup_router(
        r.f.auth.clone(),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        r.f.enrollment.clone(),
        r.f.sign_in.clone(),
        Arc::new(PasskeySignup::new(
            r.f.auth.realm(),
            r.f.service.clone(),
            r.f.store.clone(),
        )),
        Arc::new(PasskeyManagement::new(
            r.f.auth.realm(),
            r.f.service.clone(),
            r.f.store.clone(),
        )),
        Arc::new(PasskeyRecoverySetup::new(
            r.f.auth.realm(),
            r.f.service.clone(),
            r.f.store.clone(),
        )),
    )
    .unwrap();
    for app in [
        easy_auth_axum::router(r.f.auth.clone(), BrowserConfig::new(ORIGIN, false).unwrap()),
        old,
    ] {
        for path in [
            BIND,
            START,
            RESUME,
            STATUS,
            CANCEL,
            CANCEL_CODE,
            CANCEL_KEY,
            REPLACE,
            REGISTER,
            FINISH,
        ] {
            assert_eq!(
                send(&app, path, json!({}), None).await.status(),
                StatusCode::NOT_FOUND
            );
        }
    }
    let mut operation_ids = std::collections::HashSet::new();
    for path in [
        BIND,
        START,
        RESUME,
        STATUS,
        CANCEL,
        CANCEL_CODE,
        CANCEL_KEY,
        REPLACE,
        REGISTER,
        FINISH,
    ] {
        let operation = &spec["paths"][path]["post"];
        let id = operation["operationId"].as_str().unwrap();
        assert!(operation_ids.insert(id));
        for operation in prior["paths"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|path| path.as_object().unwrap().values())
        {
            assert!(
                operation
                    .get("operationId")
                    .and_then(serde_json::Value::as_str)
                    != Some(id),
                "new operation IDs must not collide with prior constructors"
            );
        }
        let reference = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
            .as_str()
            .unwrap();
        let name = reference.strip_prefix("#/components/schemas/").unwrap();
        assert_eq!(
            spec["components"]["schemas"][name]["additionalProperties"],
            false
        );
    }
    assert_eq!(
        spec["components"]["schemas"]["RecoveryCodeInput"]["properties"]["code"]["maxLength"],
        43
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn recovery_composition_rejects_every_misaligned_realm_or_origin(pool: PgPool) {
    let f = Fixture::new(pool, true).await;
    for index in 0..7 {
        for (realm, origin) in [
            (Uuid::new_v4(), ORIGIN),
            (f.auth.realm(), "https://other.example"),
        ] {
            let mut configured = services(&f);
            let service = Arc::new(PasskeyService::new(origin, "Example").unwrap());
            match index {
                0 => {
                    configured.enrollment =
                        Arc::new(PasskeyEnrollment::new(realm, service, f.store.clone()))
                }
                1 => {
                    configured.sign_in =
                        Arc::new(PasskeySignIn::new(realm, service, f.store.clone()))
                }
                2 => {
                    configured.signup =
                        Arc::new(PasskeySignup::new(realm, service, f.store.clone()))
                }
                3 => {
                    configured.management =
                        Arc::new(PasskeyManagement::new(realm, service, f.store.clone()))
                }
                4 => {
                    configured.setup =
                        Arc::new(PasskeyRecoverySetup::new(realm, service, f.store.clone()))
                }
                5 => {
                    configured.claims =
                        Arc::new(PasskeyRecoveryClaims::new(realm, service, f.store.clone()))
                }
                _ => {
                    configured.replacement = Arc::new(PasskeyRecoveryReplacement::new(
                        realm,
                        service,
                        f.store.clone(),
                    ))
                }
            }
            assert!(
                experimental_passkey_recovery_router(
                    f.auth.clone(),
                    BrowserConfig::new(ORIGIN, false).unwrap(),
                    configured
                )
                .is_err()
            );
        }
    }
}
