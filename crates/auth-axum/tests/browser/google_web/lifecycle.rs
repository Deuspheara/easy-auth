use super::setup::*;
use auth_core::*;
use axum::{body::Body, http::Request};
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test]
async fn https_google_public_authorization_callback_and_post_commit_one_protected_session(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let a = f.start(ROOT, "").await;
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    let claims = a
        .url
        .query_pairs()
        .find(|(name, _)| name == "claims")
        .unwrap()
        .1;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&claims).unwrap(),
        json!({"id_token":{"auth_time":{"essential":true}}})
    );
    assert!(
        !a.url
            .query_pairs()
            .any(|(name, _)| matches!(name.as_ref(), "prompt" | "max_age"))
    );
    let query = f.fresh(&a).await;
    let r = f
        .send(
            Request::builder()
                .uri(format!("/google/callback?{query}"))
                .header("cookie", &a.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status(), 200);
    no_session(&r);
    assert_eq!(r.headers()["referrer-policy"], "no-referrer");
    assert_eq!(r.headers()["cache-control"], "no-store");
    let html = text(r).await;
    assert!(html.contains("data-flow=\"signin\""));
    assert!(!html.contains(&query), "callback proof must not enter HTML");
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    let r = f
        .post(ROOT, "finish", json!({"query":query}), &a.cookie)
        .await;
    assert_eq!(r.status(), 204);
    let current = session(&r);
    for value in r.headers().get_all("set-cookie") {
        let value = value.to_str().unwrap();
        for flag in ["Secure", "HttpOnly", "Path=/", "SameSite=Lax"] {
            assert!(value.contains(flag), "protected host-only cookie policy");
        }
        assert!(!value.contains("Domain="));
    }
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    let r = f
        .send(
            Request::builder()
                .uri("/v1/session")
                .header("cookie", &current)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status(), 200);
    let owner = body_json(r).await;
    assert!(owner["email"].is_null());
    let token = Secret::parse(current.split_once('=').unwrap().1.to_owned()).unwrap();
    assert_eq!(
        f.store
            .authenticate(f.realm(), token.verifier())
            .await
            .unwrap()
            .authentication_policy,
        AuthenticationPolicy::ProviderRequired
    );
    let r = f
        .post(ROOT, "finish", json!({"query":query}), &a.cookie)
        .await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
}

#[sqlx::test]
async fn concurrent_google_http_finishes_exchange_and_commit_once(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start(ROOT, "").await;
    let query = f.fresh(&a).await;
    let (left, right) = tokio::join!(
        f.post(ROOT, "finish", json!({"query":query}), &a.cookie),
        f.post(ROOT, "finish", json!({"query":query}), &a.cookie)
    );
    assert!(matches!(
        (left.status().as_u16(), right.status().as_u16()),
        (204, 401) | (401, 204)
    ));
    let rejected = if left.status() == 401 { left } else { right };
    no_session(&rejected);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}

#[sqlx::test]
async fn google_http_cancel_and_provider_error_callbacks_issue_no_authority(pool: PgPool) {
    let f = Fixture::new(pool).await;
    for error in [None, Some("access_denied"), Some("server_error")] {
        let a = f.start(ROOT, "").await;
        let r = if let Some(error) = error {
            f.post(
                ROOT,
                "finish",
                json!({"query":callback(&a,None,Some(error))}),
                &a.cookie,
            )
            .await
        } else {
            f.post(ROOT, "cancel", json!({}), &a.cookie).await
        };
        assert_eq!(
            r.status().as_u16(),
            match error {
                None => 204,
                Some("access_denied") => 401,
                _ => 503,
            }
        );
        no_session(&r);
        assert!(!text(r).await.contains("private-provider-detail"));
        assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    let a = f.start(ROOT, "").await;
    let query = f.fresh(&a).await;
    assert_eq!(
        f.post(ROOT, "finish", json!({"query":query}), &a.cookie)
            .await
            .status(),
        204
    );
}
