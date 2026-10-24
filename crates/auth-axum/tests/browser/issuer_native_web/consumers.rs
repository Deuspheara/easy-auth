use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use uuid::Uuid;

async fn consumer(f: &Fixture) -> (IssuerNativeConsumerPolicy, String) {
    let secret = Secret::generate().unwrap();
    let reader = f
        .base
        .store
        .configure_issuer_client(
            &IssuerClientRegistration::confidential(
                f.base.realm,
                Uuid::new_v4(),
                &["https://resource.example/cb"],
                &secret,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{}", reader.client(), secret.expose()))
    );
    let policy = f
        .base
        .store
        .configure_issuer_native_consumer(
            &IssuerNativeConsumerPolicy::new(
                f.policy.authority().clone(),
                reader,
                f.policy.client().clone(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    (policy, basic)
}
async fn inspect(
    f: &Fixture,
    policy: &IssuerNativeConsumerPolicy,
    token: &str,
    basic: Option<&str>,
) -> Response {
    f.base
        .app
        .clone()
        .oneshot(token_request(
            "/oidc/native/introspect",
            status_body(policy.consumer().client(), token),
            basic,
            true,
        ))
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn native_consumer_is_explicit_closed_and_requires_actual_authenticated_audience_permission(
    pool: PgPool,
) {
    let f = wire_with_inspection(Fixture::new(pool).await, true);
    let (policy, basic) = consumer(&f).await;
    let tokens = issued(&f).await;
    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(inspect(&f, &policy, access, None).await.status(), 401);
    let wrong = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{}:{}",
            policy.consumer().client(),
            Secret::generate().unwrap().expose()
        ))
    );
    for token in [access, "unknown"] {
        assert_eq!(
            inspect(&f, &policy, token, Some(&wrong)).await.status(),
            401
        );
    }
    let response = inspect(&f, &policy, access, Some(&basic)).await;
    assert_eq!(response.status(), 200);
    assert_eq!(read(response).await, json!({"active":false}));
    f.base
        .store
        .enable_issuer_native_consumer(&policy)
        .await
        .unwrap();
    let response = inspect(&f, &policy, access, Some(&basic)).await;
    assert_eq!(response.status(), 200);
    for name in [header::CACHE_CONTROL, header::PRAGMA] {
        assert!(response.headers().contains_key(name));
    }
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let active = read(response).await;
    assert_eq!(active.as_object().unwrap().len(), 9);
    assert_eq!(active["active"], true);
    assert_eq!(active["aud"], f.policy.client().client().to_string());
    assert_eq!(active["client_id"], active["aud"]);
    assert_eq!(active["scope"], ISSUER_NATIVE_SCOPE);
    assert_eq!(active["iss"], f.policy.authority().issuer());
    assert_eq!(
        read(
            inspect(
                &f,
                &policy,
                tokens["refresh_token"].as_str().unwrap(),
                Some(&basic)
            )
            .await
        )
        .await,
        json!({"active":false})
    );
    let next = read(refresh(&f, tokens["refresh_token"].as_str().unwrap()).await).await;
    assert_eq!(
        read(
            inspect(
                &f,
                &policy,
                next["access_token"].as_str().unwrap(),
                Some(&basic)
            )
            .await
        )
        .await["active"],
        true
    );
    assert_eq!(
        revoke(&f, next["refresh_token"].as_str().unwrap())
            .await
            .status(),
        200
    );
    for token in [access, next["access_token"].as_str().unwrap()] {
        assert_eq!(
            read(inspect(&f, &policy, token, Some(&basic)).await).await,
            json!({"active":false})
        );
    }
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn native_consumer_route_and_live_contract_appear_only_with_explicit_composition(
    pool: PgPool,
) {
    let f = fixture(pool).await;
    let response = f
        .base
        .app
        .clone()
        .oneshot(token_request(
            "/oidc/native/introspect",
            "token=unknown".into(),
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let api = read(
        f.base
            .app
            .clone()
            .oneshot(get("/openapi.json"))
            .await
            .unwrap(),
    )
    .await;
    assert!(api["paths"].get("/oidc/native/introspect").is_none());
    let f = wire_with_inspection(f, true);
    let api = read(
        f.base
            .app
            .clone()
            .oneshot(get("/openapi.json"))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        api["paths"]["/oidc/native/introspect"]["post"]["operationId"],
        "nativeConsumerIntrospection"
    );
    assert_eq!(
        api,
        serde_json::to_value(easy_auth_axum::issuer_native_consumer_openapi()).unwrap()
    );
    let (policy, basic) = consumer(&f).await;
    f.base
        .store
        .enable_issuer_native_consumer(&policy)
        .await
        .unwrap();
    let response = inspect(&f, &policy, "unknown", Some(&basic)).await;
    assert_eq!(response.status(), 200);
    assert_eq!(read(response).await, json!({"active":false}));
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn native_consumer_reuses_strict_status_transport_and_has_no_ambient_cookie_authority(
    pool: PgPool,
) {
    let f = wire_with_inspection(Fixture::new(pool).await, true);
    let (policy, basic) = consumer(&f).await;
    for (path, body, peer, status) in [
        (
            "/oidc/native/introspect?extra=1",
            "token=unknown",
            true,
            400,
        ),
        ("/oidc/native/introspect", "token=a&%74oken=b", true, 400),
        (
            "/oidc/native/introspect",
            "token=a&client_secret=not-accepted",
            true,
            400,
        ),
        ("/oidc/native/introspect", "token=unknown", false, 503),
    ] {
        assert_eq!(
            f.base
                .app
                .clone()
                .oneshot(token_request(path, body.into(), Some(&basic), peer))
                .await
                .unwrap()
                .status(),
            status
        );
    }
    let mut request = token_request(
        "/oidc/native/introspect",
        status_body(f.policy.client().client(), "unknown"),
        None,
        true,
    );
    request
        .headers_mut()
        .insert(header::COOKIE, f.base.current.parse().unwrap());
    assert_eq!(
        f.base.app.clone().oneshot(request).await.unwrap().status(),
        401
    );
    let response = inspect(&f, &policy, &"x".repeat(4097), Some(&basic)).await;
    assert_eq!(response.status(), 413);
}
