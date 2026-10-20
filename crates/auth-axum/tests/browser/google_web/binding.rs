use super::setup::*;
use crate::support::post;
use axum::{
    body::Body,
    http::{Request, header},
};
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test]
async fn google_http_bad_or_stale_callbacks_preserve_new_pending_proof_and_never_exchange(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let old = f.start(ROOT, "").await;
    assert_eq!(
        f.post(ROOT, "cancel", json!({}), &old.cookie)
            .await
            .status(),
        204
    );
    let current = f.start(ROOT, "").await;
    let query = f.fresh(&current).await;
    let wrong_state = callback(&old, Some("owned-wrong-code"), None);
    for bad in [
        wrong_state,
        callback(&old, None, Some("access_denied")),
        format!("{query}&code=duplicate"),
        query.replace(
            "https%3A%2F%2Faccounts.google.com",
            "https%3A%2F%2Fother.example",
        ),
        format!("{query}&unknown=private"),
        "%FF".to_owned(),
    ] {
        let r = f
            .post(ROOT, "finish", json!({"query":bad}), &current.cookie)
            .await;
        assert_eq!(r.status(), 401);
        no_session(&r);
        assert!(
            r.headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .next()
                .is_none(),
            "invalid/stale callback cannot clear newer proof cookies"
        );
        assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.post(ROOT, "finish", json!({"query":query}), &current.cookie)
            .await
            .status(),
        204
    );
}

#[sqlx::test]
async fn google_http_private_browser_proof_and_realm_binding_precede_token_post(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let other = Fixture::with_origin(pool, "https://other.example").await;
    let a = f.start(ROOT, "").await;
    let foreign = other.start(ROOT, "").await;
    let query = f.fresh(&a).await;
    // Keep the original state but replace one private proof field at a time.
    let fields: Vec<_> = a.cookie.split("; ").collect();
    let foreign_fields: Vec<_> = foreign.cookie.split("; ").collect();
    for field in [0, 2, 3] {
        let mut tampered = fields.clone();
        tampered[field] = foreign_fields[field];
        let r = f
            .post(ROOT, "finish", json!({"query":query}), &tampered.join("; "))
            .await;
        assert_eq!(r.status(), 401);
        no_session(&r);
        assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    }
    let r = other
        .post(ROOT, "finish", json!({"query":query}), &a.cookie)
        .await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(other.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.post(ROOT, "finish", json!({"query":query}), &a.cookie)
            .await
            .status(),
        204
    );
    assert_eq!(
        other
            .post(ROOT, "cancel", json!({}), &foreign.cookie)
            .await
            .status(),
        204
    );
}

#[sqlx::test]
async fn google_http_existing_session_presence_prevents_implicit_account_switch(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start(ROOT, "").await;
    let query = f.fresh(&a).await;
    for cookie in [
        format!("{}; __Host-auth-session=invalid", a.cookie),
        format!("{}; __Host-auth-session", a.cookie),
    ] {
        for action in ["start", "finish"] {
            let body = if action == "finish" {
                json!({"query":query})
            } else {
                json!({})
            };
            let r = f
                .send(post(
                    &format!("{ROOT}/{action}"),
                    &body.to_string(),
                    Some(&cookie),
                    Some(ORIGIN),
                ))
                .await;
            assert_eq!(r.status(), 401);
            no_session(&r);
        }
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    let current = f.signin().await;
    let r = f
        .post(
            ROOT,
            "finish",
            json!({"query":query}),
            &format!("{}; {current}", a.cookie),
        )
        .await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    assert_eq!(
        f.post(
            ROOT,
            "cancel",
            json!({}),
            &format!("{}; {current}", a.cookie)
        )
        .await
        .status(),
        204
    );
    assert_eq!(
        f.send(
            Request::builder()
                .uri("/v1/session")
                .header("cookie", current)
                .body(Body::empty())
                .unwrap()
        )
        .await
        .status(),
        200
    );
}
