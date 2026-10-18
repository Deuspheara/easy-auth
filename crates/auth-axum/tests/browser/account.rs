use crate::support::*;
use auth_core::Auth;
use auth_postgres::Postgres;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use easy_auth_axum::BrowserConfig;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

#[sqlx::test]
async fn account_lifecycle_http_with_email_only_account(pool: PgPool) {
    let store = Postgres::new(pool.clone());
    store.migrate().await.unwrap();
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    let mail = Arc::new(Mail::default());
    let auth = Auth::new(realm, Arc::new(store), mail.clone());
    let app = easy_auth_axum::router(
        auth.clone(),
        BrowserConfig::new("https://app.example", false).unwrap(),
    );
    let current = sign_in(&app, &mail, "alice@example.com").await;
    let old_user: Uuid = sqlx::query_scalar("SELECT id FROM auth_users WHERE realm_id=$1")
        .bind(realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    let change = r#"{"email":"new@example.com"}"#;
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/v1/account/email/start",
                change,
                Some(&current),
                None
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let started = app
        .clone()
        .oneshot(post(
            "/v1/account/email/start",
            change,
            Some(&current),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::ACCEPTED);
    let binding = cookie(&started, "__Host-auth-email-change=");
    let cookies = format!("{current}; {binding}");
    let messages = mail.4.lock().unwrap().clone();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].0, "alice@example.com");
    assert_eq!(messages[1].0, "new@example.com");
    for (i, (_, token)) in messages.iter().enumerate() {
        let response = app
            .clone()
            .oneshot(post(
                "/v1/account/email/confirm",
                &serde_json::json!({"token":token}).to_string(),
                Some(&cookies),
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if i == 0 {
                StatusCode::ACCEPTED
            } else {
                StatusCode::NO_CONTENT
            }
        );
    }
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/session")
                    .header(header::COOKIE, &current)
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(auth.deliver_security_notice().await.unwrap());
    let current = sign_in(&app, &mail, "new@example.com").await;
    let new_user: Uuid = sqlx::query_scalar("SELECT id FROM auth_users WHERE realm_id=$1")
        .bind(realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(old_user, new_user);
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/v1/account/delete/start",
                r#"{"confirmation":"wrong"}"#,
                Some(&current),
                Some("https://app.example")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let started = app
        .clone()
        .oneshot(post(
            "/v1/account/delete/start",
            r#"{"confirmation":"delete my account"}"#,
            Some(&current),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::ACCEPTED);
    let binding = cookie(&started, "__Host-auth-delete=");
    let cookies = format!("{current}; {binding}");
    let token = mail.5.lock().unwrap().last().unwrap().clone();
    let body = serde_json::json!({"token":token,"confirmation":"delete my account"}).to_string();
    let completed = app
        .clone()
        .oneshot(post(
            "/v1/account/delete/finish",
            &body,
            Some(&cookies),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::NO_CONTENT);
    assert!(
        completed
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|h| h.to_str().unwrap().contains("Max-Age=0"))
    );
    assert_eq!(
        app.oneshot(
            Request::builder()
                .uri("/v1/session")
                .header(header::COOKIE, &current)
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_users WHERE realm_id=$1")
        .bind(realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert!(auth.deliver_security_notice().await.unwrap());
    assert_eq!(*mail.2.lock().unwrap(), 2);
}
