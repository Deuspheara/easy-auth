use super::{get, json};
use crate::support::{app, cookie, post, sign_in};
use axum::http::{StatusCode, header};
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test]
async fn revoke_all_clears_cookies_sessions_and_pending_mail_proof_in_only_its_realm(pool: PgPool) {
    let (foreign_app, foreign_mail) = app(pool.clone()).await;
    let foreign = sign_in(&foreign_app, &foreign_mail, "alice@example.com").await;
    let (app, mail) = app(pool).await;
    let first = sign_in(&app, &mail, "alice@example.com").await;
    let second = sign_in(&app, &mail, "alice@example.com").await;
    let bob = sign_in(&app, &mail, "bob@example.com").await;
    let pending = app
        .clone()
        .oneshot(post(
            "/v1/email/start",
            r#"{"email":"alice@example.com"}"#,
            None,
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(pending.status(), StatusCode::ACCEPTED);
    let binding = cookie(&pending, "__Host-auth-browser=");
    let token = mail.0.lock().unwrap().last().unwrap().clone();
    for (body, origin, status) in [
        ("{}", None, StatusCode::FORBIDDEN),
        (
            r#"{"user_id":"untrusted"}"#,
            Some("https://app.example"),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let result = app
            .clone()
            .oneshot(post("/v1/sessions/revoke-all", body, Some(&first), origin))
            .await
            .unwrap();
        assert_eq!(result.status(), status);
        assert_eq!(
            get(&app, "/v1/session", &first).await.status(),
            StatusCode::OK
        );
    }
    let result = app
        .clone()
        .oneshot(post(
            "/v1/sessions/revoke-all",
            "{}",
            Some(&first),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        result.headers().get_all(header::SET_COOKIE).iter().count(),
        5
    );
    assert!(
        result
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|h| h.to_str().unwrap().contains("Max-Age=0"))
    );
    for old in [&first, &second] {
        assert_eq!(
            get(&app, "/v1/session", old).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        get(&app, "/v1/session", &bob).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        get(&foreign_app, "/v1/session", &foreign).await.status(),
        StatusCode::OK
    );
    let result = app
        .clone()
        .oneshot(post(
            "/v1/email/finish",
            &serde_json::json!({"token":token}).to_string(),
            Some(&binding),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
    // A genuine new sign-in is allowed after revocation; credentials were not disabled.
    let new = sign_in(&app, &mail, "alice@example.com").await;
    assert_eq!(
        get(&app, "/v1/session", &new).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        json(get(&app, "/v1/sessions", &new).await).await["sessions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
