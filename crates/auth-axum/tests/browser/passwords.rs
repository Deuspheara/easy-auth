use crate::support::*;
use auth_core::{Auth, Secret};
use auth_postgres::Postgres;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use easy_auth_axum::BrowserConfig;
use http_body_util::BodyExt;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

#[sqlx::test]
async fn password_enrollment_and_login_use_shared_sessions(pool: PgPool) {
    let (app, mail) = app(pool.clone()).await;
    let previous = sign_in(&app, &mail, "alice@example.com").await;
    let good = serde_json::json!({"password":"correct horse sample password"}).to_string();
    let blocked = serde_json::json!({"password":"a compromised example password"}).to_string();
    for (body, session, origin, status) in [
        (
            &good,
            None,
            Some("https://app.example"),
            StatusCode::UNAUTHORIZED,
        ),
        (&good, Some(previous.as_str()), None, StatusCode::FORBIDDEN),
        (
            &blocked,
            Some(previous.as_str()),
            Some("https://app.example"),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(post("/v1/password/enroll", body, session, origin))
                .await
                .unwrap()
                .status(),
            status
        );
    }
    let enrolled = app
        .clone()
        .oneshot(post(
            "/v1/password/enroll",
            &good,
            Some(&previous),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(enrolled.status(), StatusCode::NO_CONTENT);
    let replacement = cookie(&enrolled, "__Host-auth-session=");
    assert_ne!(replacement, previous);
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/session")
                    .header(header::COOKIE, &previous)
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/v1/password/enroll",
                &good,
                Some(&replacement),
                Some("https://app.example")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // Unknown user, email-only user and wrong password share status/body; no credential detail is reflected.
    sign_in(&app, &mail, "email-only@example.com").await;
    let mut errors = Vec::new();
    for email in [
        "missing@example.com",
        "alice@example.com",
        "email-only@example.com",
    ] {
        let body = serde_json::json!({"email":email,"password":"an incorrect example password"})
            .to_string();
        let rejected = app
            .clone()
            .oneshot(post(
                "/v1/password/login",
                &body,
                None,
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
        errors.push(rejected.into_body().collect().await.unwrap().to_bytes());
    }
    assert_eq!(errors[0], errors[1]);
    assert_eq!(errors[0], errors[2]);
    let login =
        serde_json::json!({"email":"ALICE@example.com","password":"correct horse sample password"})
            .to_string();
    let logged_in = app
        .clone()
        .oneshot(post(
            "/v1/password/login",
            &login,
            Some(&replacement),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(logged_in.status(), StatusCode::NO_CONTENT);
    let session = cookie(&logged_in, "__Host-auth-session=");
    assert_ne!(session, replacement);
    let user = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/session")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(user.status(), StatusCode::OK);
    assert_eq!(user.headers()[header::CACHE_CONTROL], "no-store");
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM auth_password_credentials")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(hash.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
    assert!(!hash.contains("correct horse"));
    assert_eq!(
        app.oneshot(post(
            "/v1/logout",
            "{}",
            Some(&session),
            Some("https://app.example")
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::NO_CONTENT
    );
}

#[sqlx::test]
async fn password_feature_without_corpus_is_unavailable(pool: PgPool) {
    let store = Postgres::new(pool);
    store.migrate().await.unwrap();
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    let app = easy_auth_axum::router(
        Auth::new(realm, Arc::new(store), Arc::new(Mail::default())),
        BrowserConfig::new("https://app.example", false).unwrap(),
    );
    let secret = Secret::generate().unwrap();
    let cookie = format!("__Host-auth-session={}", secret.expose());
    for (path, body) in [
        (
            "/v1/password/enroll",
            r#"{"password":"synthetic example password"}"#,
        ),
        (
            "/v1/password/login",
            r#"{"email":"nobody@example.com","password":"synthetic example password"}"#,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(post(path, body, Some(&cookie), Some("https://app.example")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
