use super::{get, json};
use crate::support::{app, post, sign_in};
use axum::http::StatusCode;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

#[sqlx::test]
async fn session_controls_reject_stale_auth_duplicate_cookies_and_untrusted_queries(pool: PgPool) {
    let (app, mail) = app(pool.clone()).await;
    let current = sign_in(&app, &mail, "alice@example.com").await;
    for query in [
        "?after=must-not-echo",
        "?after=x&after=y",
        "?user_id=must-not-echo",
    ] {
        let response = get(&app, &format!("/v1/sessions{query}"), &current).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json(response).await,
            serde_json::json!({"code":"invalid_input"})
        );
    }
    let response = get(&app, "/v1/sessions", &format!("{current}; {current}")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let id = json(get(&app, "/v1/sessions", &current).await).await["sessions"][0]["id"].clone();
    let invalid = app
        .clone()
        .oneshot(post(
            "/v1/sessions/revoke",
            r#"{"id":"must-not-echo"}"#,
            Some(&current),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json(invalid).await,
        serde_json::json!({"code":"invalid_body"})
    );
    let empty = get(
        &app,
        &format!("/v1/sessions?after={}", Uuid::max()),
        &current,
    )
    .await;
    assert_eq!(json(empty).await["sessions"], serde_json::json!([]));
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        get(&app, "/v1/sessions", &current).await.status(),
        StatusCode::OK
    );
    for (path, body) in [
        (
            "/v1/sessions/revoke",
            serde_json::json!({"id":id}).to_string(),
        ),
        ("/v1/sessions/revoke-all", "{}".into()),
    ] {
        let response = app
            .clone()
            .oneshot(post(
                path,
                &body,
                Some(&current),
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let logout = app
        .clone()
        .oneshot(post(
            "/v1/logout",
            "{}",
            Some(&current),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
}
