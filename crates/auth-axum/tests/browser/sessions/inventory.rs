use super::{get, json};
use crate::support::{app, post, sign_in};
use axum::http::{StatusCode, header};
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test]
async fn inventory_and_individual_revocation_never_expose_secrets_or_select_other_users(
    pool: PgPool,
) {
    let (app, mail) = app(pool).await;
    let first = sign_in(&app, &mail, "alice@example.com").await;
    let second = sign_in(&app, &mail, "alice@example.com").await;
    let bob = sign_in(&app, &mail, "bob@example.com").await;
    let response = get(&app, "/v1/sessions", &first).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let page = json(response).await;
    let sessions = page["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(page["next"].is_null());
    for s in sessions {
        let mut keys: Vec<_> = s.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "authenticated_at_ms",
                "created_at_ms",
                "current",
                "expires_at_ms",
                "id",
                "idle_expires_at_ms",
                "last_seen_at_ms"
            ]
        );
        assert!(s["authenticated_at_ms"].is_i64());
        assert!(s["idle_expires_at_ms"].as_i64().unwrap() <= s["expires_at_ms"].as_i64().unwrap());
    }
    let serialized = page.to_string();
    for cookie in [&first, &second, &bob] {
        assert!(!serialized.contains(cookie.split_once('=').unwrap().1));
    }
    let current = sessions.iter().find(|s| s["current"] == true).unwrap()["id"].clone();
    let target = sessions.iter().find(|s| s["current"] == false).unwrap()["id"].clone();
    let input = serde_json::json!({"id":target}).to_string();
    let foreign = app
        .clone()
        .oneshot(post(
            "/v1/sessions/revoke",
            &input,
            Some(&bob),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NO_CONTENT);
    assert!(!foreign.headers().contains_key(header::SET_COOKIE));
    assert_eq!(
        get(&app, "/v1/session", &second).await.status(),
        StatusCode::OK
    );
    for _ in 0..2 {
        let result = app
            .clone()
            .oneshot(post(
                "/v1/sessions/revoke",
                &input,
                Some(&first),
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::NO_CONTENT);
        assert!(!result.headers().contains_key(header::SET_COOKIE));
    }
    assert_eq!(
        get(&app, "/v1/session", &second).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let own = app
        .clone()
        .oneshot(post(
            "/v1/sessions/revoke",
            &serde_json::json!({"id":current}).to_string(),
            Some(&first),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(own.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        own.headers().get_all(header::SET_COOKIE).iter().count(),
        5 + usize::from(cfg!(feature = "passkey-enrollment"))
            + usize::from(cfg!(feature = "passkey-signup"))
    );
    #[cfg(feature = "passkey-enrollment")]
    assert!(
        own.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| value.to_str().unwrap().starts_with("__Host-auth-passkey=;"))
    );
    assert!(
        own.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|h| h.to_str().unwrap().contains("Max-Age=0"))
    );
    assert_eq!(
        get(&app, "/v1/sessions", &first).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(&app, "/v1/session", &bob).await.status(),
        StatusCode::OK
    );
}
