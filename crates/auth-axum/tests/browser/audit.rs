use crate::support::{app, cookie, post, sign_in};
use axum::http::StatusCode;
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test]
async fn real_password_and_recovery_inputs_never_enter_audit_and_untrusted_context_is_rejected(
    pool: PgPool,
) {
    let (app, mail) = app(pool.clone()).await;
    let email = "audit-http@example.com";
    let current = sign_in(&app, &mail, email).await;
    let password = "synthetic audit plaintext before recovery";
    let after = "synthetic audit plaintext after recovery";
    let enrollment = app
        .clone()
        .oneshot(post(
            "/v1/password/enroll",
            &serde_json::json!({"password":password}).to_string(),
            Some(&current),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(enrollment.status(), StatusCode::NO_CONTENT);
    let replacement = cookie(&enrollment, "__Host-auth-session=");
    let stored: String = sqlx::query_scalar("SELECT password_hash FROM auth_password_credentials")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(stored.starts_with("$argon2id$"));
    let rejected=app.clone().oneshot(post("/v1/password/enroll",&serde_json::json!({"password":password,"context":"must-not-persist-arbitrary-context"}).to_string(),Some(&replacement),Some("https://app.example"))).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let reset = app
        .clone()
        .oneshot(post(
            "/v1/password/reset/start",
            &serde_json::json!({"email":email}).to_string(),
            None,
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(reset.status(), StatusCode::ACCEPTED);
    let binding = cookie(&reset, "__Host-auth-reset=");
    let proof = mail.1.lock().unwrap().last().unwrap().clone();
    let finish = app
        .clone()
        .oneshot(post(
            "/v1/password/reset/finish",
            &serde_json::json!({"token":proof,"password":after}).to_string(),
            Some(&binding),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(finish.status(), StatusCode::NO_CONTENT);
    let audit: Vec<String> =
        sqlx::query_scalar("SELECT to_jsonb(a)::text FROM auth_audit a ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(audit.len(), 3);
    let audit = audit.join("\n");
    assert!(audit.contains("password_reset"));
    for forbidden in [
        email,
        password,
        after,
        &stored,
        &proof,
        "must-not-persist-arbitrary-context",
        current.split_once('=').unwrap().1,
        replacement.split_once('=').unwrap().1,
        binding.split_once('=').unwrap().1,
    ] {
        assert!(!audit.contains(forbidden));
    }
    let recovery:(i16,Option<uuid::Uuid>,Option<uuid::Uuid>,bool)=sqlx::query_as("SELECT schema_version,actor_session_id,session_id,subject_erased FROM auth_audit WHERE kind='password_reset'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(recovery, (1, None, None, false));
}
