use super::{get, json};
use crate::support::{app, post};
use auth_core::Secret;
use axum::http::StatusCode;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

#[sqlx::test]
async fn email_free_session_has_explicit_null_contact_and_safe_sensitive_routes(pool: PgPool) {
    let (app, mail) = app(pool.clone()).await;
    let realm: Uuid = sqlx::query_scalar("SELECT id FROM auth_realms")
        .fetch_one(&pool)
        .await
        .unwrap();
    let user = Uuid::new_v4();
    // This tests the HTTP contract against trusted storage fixtures, not signup
    // or private-key proof. Native anonymous signup remains separate evidence.
    sqlx::query("INSERT INTO auth_users(realm_id,id,email,email_verified_at,display_name,authentication_policy) VALUES ($1,$2,NULL,NULL,'Person <label>','passkey_required')")
        .bind(realm).bind(user).execute(&pool).await.unwrap();
    let secret = Secret::generate().unwrap();
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,'passkey')")
        .bind(realm).bind(Uuid::new_v4()).bind(user).bind(secret.verifier().as_slice())
        .execute(&pool).await.unwrap();
    let cookie = format!("__Host-auth-session={}", secret.expose());
    let response = get(&app, "/v1/session", &cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = json(response).await;
    assert_eq!(
        value,
        serde_json::json!({"id":user,"realm_id":realm,"email":null,"display_name":"Person <label>"})
    );
    assert_eq!(
        get(&app, "/v1/sessions", &cookie).await.status(),
        StatusCode::OK
    );
    for (path, body) in [
        (
            "/v1/password/enroll",
            r#"{"password":"a sufficiently long example"}"#,
        ),
        ("/v1/account/email/start", r#"{"email":"new@example.com"}"#),
        (
            "/v1/account/delete/start",
            r#"{"confirmation":"delete my account"}"#,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(post(path, body, Some(&cookie), Some("https://app.example")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json(response).await,
            serde_json::json!({"code":"authentication_required"})
        );
    }
    assert!(mail.changes.lock().unwrap().is_empty());
    assert!(mail.deletions.lock().unwrap().is_empty());
    let response = app
        .clone()
        .oneshot(post(
            "/v1/sessions/revoke-all",
            "{}",
            Some(&cookie),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        get(&app, "/v1/session", &cookie).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let user_buckets: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_rate_buckets WHERE dimension='sensitive_user'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(user_buckets, 1);
}
