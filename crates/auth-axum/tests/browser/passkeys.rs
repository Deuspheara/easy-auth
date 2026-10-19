use crate::support::{Mail, cookie, post, sign_in};
use auth_core::{Auth, PasskeyEnrollment, PasskeyService};
use auth_postgres::Postgres;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use easy_auth_axum::{
    BrowserConfig, experimental_passkey_enrollment_router, passkey_enrollment_openapi,
};
use http_body_util::BodyExt;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn app(pool: PgPool) -> (Router, Arc<Mail>, Auth) {
    let store = Arc::new(Postgres::new(pool));
    store.migrate().await.unwrap();
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    let mail = Arc::new(Mail::default());
    let auth = Auth::new(realm, store.clone(), mail.clone());
    let enrollment = Arc::new(PasskeyEnrollment::new(
        realm,
        Arc::new(PasskeyService::new("https://app.example", "Example").unwrap()),
        store,
    ));
    let app = experimental_passkey_enrollment_router(
        auth.clone(),
        BrowserConfig::new("https://app.example", false).unwrap(),
        enrollment,
    )
    .unwrap();
    (app, mail, auth)
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn experimental_http_enrollment_enforces_browser_boundary_and_never_returns_private_state(
    pool: PgPool,
) {
    let (app, mail, auth) = app(pool.clone()).await;
    let session = sign_in(&app, &mail, "alice@example.com").await;
    for (origin, expected) in [
        (None, StatusCode::FORBIDDEN),
        (Some("https://evil.example"), StatusCode::FORBIDDEN),
        (Some("https://app.example"), StatusCode::UNAUTHORIZED),
    ] {
        let result = app
            .clone()
            .oneshot(post(
                "/v1/passkeys/enrollment/start",
                "{\"label\":\"key\"}",
                None,
                origin,
            ))
            .await
            .unwrap();
        assert_eq!(result.status(), expected);
    }
    let started = app
        .clone()
        .oneshot(post(
            "/v1/passkeys/enrollment/start",
            "{\"label\":\"key\"}",
            Some(&session),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::OK);
    assert_eq!(started.headers()[header::CACHE_CONTROL], "no-store");
    let set_cookie = started
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .next()
        .unwrap()
        .to_str()
        .unwrap();
    for required in [
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=120",
    ] {
        assert!(set_cookie.contains(required));
    }
    assert!(!set_cookie.contains("Domain="));
    let binding = cookie(&started, "__Host-auth-passkey=");
    let body = started.into_body().collect().await.unwrap().to_bytes();
    let options: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(options.as_object().unwrap().len(), 2);
    assert!(options.get("transaction_id").is_some());
    assert_eq!(options["options"]["publicKey"]["rp"]["id"], "app.example");
    assert_eq!(
        options["options"]["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert!(!String::from_utf8_lossy(&body).contains("private_state"));
    let malformed=serde_json::json!({"transaction_id":options["transaction_id"],"credential":{
        "id":"AQ","rawId":"AQ","type":"public-key","response":{"attestationObject":"AA","clientDataJSON":"e30"}}}).to_string();
    let cookies = format!("{session}; {binding}");
    let rejected = app
        .clone()
        .oneshot(post(
            "/v1/passkeys/enrollment/finish",
            &malformed,
            Some(&cookies),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        rejected.into_body().collect().await.unwrap().to_bytes(),
        "{\"code\":\"authentication_required\"}"
    );
    let duplicate = format!("{cookies}; {binding}");
    let rejected = app
        .clone()
        .oneshot(post(
            "/v1/passkeys/enrollment/start",
            "{\"label\":\"key\"}",
            Some(&duplicate),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE realm_id=$1")
        .bind(auth.realm())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn enrollment_http_is_opt_in_bounded_and_has_a_concrete_full_contract(pool: PgPool) {
    let (app, mail, auth) = app(pool.clone()).await;
    let session = sign_in(&app, &mail, "alice@example.com").await;
    let normal = easy_auth_axum::router(
        auth.clone(),
        BrowserConfig::new("https://app.example", false).unwrap(),
    );
    let absent = normal
        .oneshot(post(
            "/v1/passkeys/enrollment/start",
            "{}",
            Some(&session),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(absent.status(), StatusCode::NOT_FOUND);
    for (body, expected) in [
        (
            serde_json::json!({"label":"key","user_id":Uuid::new_v4()}).to_string(),
            StatusCode::BAD_REQUEST,
        ),
        (
            serde_json::json!({"label":"x".repeat(9000)}).to_string(),
            StatusCode::BAD_REQUEST,
        ),
        (
            serde_json::json!({"label":"x".repeat(33000)}).to_string(),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        let rejected = app
            .clone()
            .oneshot(post(
                "/v1/passkeys/enrollment/start",
                &body,
                Some(&session),
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(rejected.status(), expected);
    }
    let spec = serde_json::to_value(passkey_enrollment_openapi()).unwrap();
    let base = serde_json::to_value(easy_auth_axum::openapi()).unwrap();
    for (name, schema) in base["components"]["schemas"].as_object().unwrap() {
        assert_eq!(
            &spec["components"]["schemas"][name], schema,
            "base schema {name} changed"
        );
    }
    assert_eq!(
        spec["paths"]["/v1/passkeys/enrollment/finish"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["$ref"],
        "#/components/schemas/PasskeyEnrollmentFinishInput"
    );
    let finish = &spec["components"]["schemas"]["PasskeyEnrollmentFinishInput"]["properties"];
    assert!(finish.get("transaction_id").is_some());
    assert!(finish.get("credential").is_some());
    assert!(finish.get("token").is_none());
    let published: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/architecture/openapi-passkey-enrollment.json"
    ))
    .unwrap();
    assert_eq!(
        spec, published,
        "regenerate the experimental enrollment OpenAPI snapshot"
    );
    for route in [
        "/v1/email/start",
        "/v1/passkeys/enrollment/start",
        "/v1/passkeys/enrollment/finish",
    ] {
        assert!(spec["paths"].get(route).is_some());
    }
    assert!(
        spec["components"]["schemas"]["WebAuthnRegistrationResponse"]["properties"]["response"]
            .is_object()
    );
    assert!(
        spec["components"]["schemas"]["AttestationResponse"]["properties"]
            .get("clientDataJSON")
            .is_some()
    );
    let served = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(served.status(), StatusCode::OK);
    let served: serde_json::Value =
        serde_json::from_slice(&served.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(served, spec);
    let store = Arc::new(Postgres::new(pool));
    for (realm, origin) in [
        (Uuid::new_v4(), "https://app.example"),
        (auth.realm(), "https://other.example"),
    ] {
        let enrollment = Arc::new(PasskeyEnrollment::new(
            realm,
            Arc::new(PasskeyService::new(origin, "Example").unwrap()),
            store.clone(),
        ));
        assert!(
            experimental_passkey_enrollment_router(
                auth.clone(),
                BrowserConfig::new("https://app.example", false).unwrap(),
                enrollment
            )
            .is_err()
        );
    }
}
