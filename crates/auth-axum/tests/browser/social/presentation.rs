use super::setup::*;
use easy_auth_axum::{
    BrowserConfig, experimental_apple_web_router, experimental_google_web_router,
};
use tower::ServiceExt;

#[sqlx::test]
async fn callback_presentation_requires_explicit_selection_and_unique_state_without_consumption(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (owner, session) = f.owner("owner@owned.example").await;
    let google = f.start("google", owner, &session).await;
    let raw = f.issue("google", &google, "g").await;
    let path = format!("/google/callback?{raw}");
    let r = f.get(&path, &google.cookie).await;
    assert_eq!(r.status(), 200);
    no_session(&r);
    assert!(text(r).await.contains("/social/google-return.js"));
    let default = experimental_google_web_router(
        f.auth.clone(),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        f.google_services.clone(),
    )
    .unwrap();
    let r = default
        .oneshot(
            Request::builder()
                .uri(&path)
                .header("cookie", &google.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!text(r).await.contains("/social/google-return.js"));
    let duplicate = format!(
        "{}; __Host-auth-google-signin-state={}",
        google.cookie,
        google.field("state")
    );
    assert!(
        !text(f.get(&path, &duplicate).await)
            .await
            .contains("/social/google-return.js")
    );
    assert_eq!(f.finish("google", &google, &raw).await.status(), 204);
    let apple = f.start("apple", owner, &session).await;
    let raw = f.issue("apple", &apple, "a").await;
    let input = json!({"state":apple.field("state")});
    let r = f
        .post("/v1/apple/return-operation", input.clone(), &apple.cookie)
        .await;
    assert_eq!(r.status(), 200);
    no_session(&r);
    assert_eq!(body(r).await, "link_identity");
    let default = experimental_apple_web_router(
        f.auth.clone(),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        f.apple_services.clone(),
    )
    .unwrap();
    let r = default
        .oneshot(crate::support::post(
            "/v1/apple/return-operation",
            &input.to_string(),
            Some(&apple.cookie),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let duplicate = format!(
        "{}; __Host-auth-apple-signin-state={}",
        apple.cookie,
        apple.field("state")
    );
    assert_eq!(
        f.post("/v1/apple/return-operation", input, &duplicate)
            .await
            .status(),
        401
    );
    assert_eq!(f.finish("apple", &apple, &raw).await.status(), 204);
}

#[sqlx::test]
async fn apple_delivery_and_operation_hint_are_non_authoritative_and_origin_separated(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (owner, session) = f.owner("owner@owned.example").await;
    let a = f.start("apple", owner, &session).await;
    let raw = f.issue("apple", &a, "delivery").await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_audit")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    let r = f
        .send(
            Request::builder()
                .method("POST")
                .uri("/apple/callback")
                .header("origin", "https://appleid.apple.com")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", "malformed; duplicate=1; duplicate=2")
                .body(Body::from(raw.clone()))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status(), 200);
    assert!(r.headers().get_all("set-cookie").iter().next().is_none());
    let r = f
        .post(
            "/v1/apple/return-operation",
            json!({"state":a.field("state")}),
            &a.cookie,
        )
        .await;
    assert_eq!(r.status(), 200);
    assert!(r.headers().get_all("set-cookie").iter().next().is_none());
    assert_eq!(f.apple.posts.load(std::sync::atomic::Ordering::SeqCst), 0);
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_audit")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(before, after);
    // Closed JSON members are malformed bodies (400); Secret deliberately uses
    // the existing non-disclosing authentication rejection for invalid state (401).
    for (input, expected) in [
        (json!({"state":a.field("state"),"code":"rejected"}), 400),
        (json!({"state":"invalid"}), 401),
    ] {
        assert_eq!(
            f.post("/v1/apple/return-operation", input, &a.cookie)
                .await
                .status(),
            expected
        );
    }
    let input = json!({"state":a.field("state")});
    let r = f
        .send(crate::support::post(
            "/v1/apple/return-operation",
            &input.to_string(),
            Some(&a.cookie),
            Some("https://appleid.apple.com"),
        ))
        .await;
    assert_eq!(r.status(), 403);
    assert_eq!(f.finish("apple", &a, &raw).await.status(), 204);
}

#[sqlx::test]
async fn selected_contract_and_pages_do_not_enable_ordinary_builders(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let api = body(f.get("/openapi.json", "").await).await;
    assert_eq!(
        api,
        serde_json::to_value(easy_auth_axum::social_web_openapi()).unwrap()
    );
    for path in [
        "/v1/account/google-link/start",
        "/v1/account/apple-link/finish",
        "/v1/account/providers/oidc/unlink",
    ] {
        assert!(api["paths"].get(path).is_some());
        assert!(
            serde_json::to_value(easy_auth_axum::apple_web_openapi()).unwrap()["paths"]
                .get(path)
                .is_none()
        );
        assert!(
            serde_json::to_value(easy_auth_axum::google_web_openapi()).unwrap()["paths"]
                .get(path)
                .is_none()
        );
    }
    assert!(
        easy_auth_axum::experimental_social_web_router(
            f.auth.clone(),
            BrowserConfig::new("https://wrong.example", false).unwrap(),
            f.services.clone()
        )
        .is_err()
    );
    let r = f.get("/social/accounts", "").await;
    assert_eq!(r.status(), 200);
    no_session(&r);
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert_eq!(r.headers()["referrer-policy"], "no-referrer");
    assert!(
        r.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'none'")
    );
    assert!(
        text(r)
            .await
            .contains("Unlinking here does not revoke remote Apple grants")
    );
}

#[sqlx::test]
async fn social_logout_clears_all_five_proof_sets_without_linking(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (_, session) = f.owner("owner@owned.example").await;
    let r = f.post("/v1/logout", json!({}), &session).await;
    assert_eq!(r.status(), 204);
    let clears = cookies(&r);
    for name in [
        "google-signin",
        "google-delete",
        "apple-signin",
        "google-link",
        "apple-link",
    ] {
        for part in ["browser", "state", "nonce", "pkce"] {
            assert!(
                clears.contains(&format!("__Host-auth-{name}-{part}=;"))
                    || clears.ends_with(&format!("__Host-auth-{name}-{part}="))
            );
        }
    }
    assert_eq!(f.get("/v1/session", &session).await.status(), 401);
}
