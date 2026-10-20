use super::setup::*;
use auth_core::Secret;
use axum::{
    body::Body,
    http::{Request, header},
};
use sqlx::PgPool;
use std::sync::atomic::Ordering;

async fn callback(f: &Fixture, query: &str, cookie: &str) -> axum::response::Response {
    f.send(
        Request::builder()
            .uri(format!("/oidc/callback?{query}"))
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}
#[sqlx::test]
async fn callback_selects_only_unique_exact_state_hint_and_never_consumes(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let state = a.params["state"].clone();
    let query = format!("state={state}&code=private-owned-code&iss=https%3A%2F%2Fissuer.example");
    for (cookie, title) in [
        (a.cookie.clone(), "<title>Provider sign-in</title>"),
        (
            format!("__Host-auth-oidc-delete-state={state}"),
            "<title>Delete provider account</title>",
        ),
        (
            format!("{}; __Host-auth-oidc-delete-state={state}", a.cookie),
            "<title>Provider callback unavailable</title>",
        ),
        (
            "".to_owned(),
            "<title>Provider callback unavailable</title>",
        ),
        (
            format!("{}; __Host-auth-oidc-signin-state={state}", a.cookie),
            "<title>Provider callback unavailable</title>",
        ),
    ] {
        let r = callback(&f, &query, &cookie).await;
        assert_eq!(r.status(), 200);
        no_session(&r);
        assert_eq!(r.headers().get_all(header::SET_COOKIE).iter().count(), 0);
        assert_eq!(r.headers()["cache-control"], "no-store");
        assert_eq!(r.headers()["referrer-policy"], "no-referrer");
        let html = text(r).await;
        assert!(html.contains(title));
        assert!(!html.contains(&state));
        assert!(!html.contains("private-owned-code"));
        assert_eq!(f.facts().await, (0, 0, 0, 1));
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.post("finish", a.callback, &a.cookie).await.status(), 204);
}

#[sqlx::test]
async fn malformed_denied_duplicate_and_oversized_callbacks_serve_fixed_error(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let state = &a.params["state"];
    let valid = format!("state={state}&code=owned-code");
    for query in [
        "".to_owned(),
        format!("state={state}"),
        format!("{valid}&state={state}"),
        format!("{valid}&code=other"),
        format!("{valid}&iss=a&iss=b"),
        format!("{valid}&unexpected=private-detail"),
        format!("state={state}&error=access_denied&error_description=private-detail"),
        format!("{valid}&iss=%GG"),
        format!("{valid}&iss=%FF"),
        format!("state={state}&code=%00"),
        format!("state={state}&code={}", "a".repeat(2049)),
        format!("{valid}&session_state={}", "x".repeat(8192)),
        format!(
            "state={}&code=owned-code",
            Secret::generate().unwrap().expose()
        ),
    ] {
        let r = callback(&f, &query, &a.cookie).await;
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers().get_all(header::SET_COOKIE).iter().count(), 0);
        let html = text(r).await;
        assert!(html.contains("<title>Provider callback unavailable</title>"));
        assert!(!html.contains(state));
        assert!(!html.contains("private-detail"));
    }
    assert_eq!(f.facts().await, (0, 0, 0, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.post("finish", a.callback, &a.cookie).await.status(), 204);
}
