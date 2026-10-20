use super::setup::*;
use auth_core::MAX_OIDC_DELETION_AUTH_AGE_SECONDS;
use axum::{body::Body, http::Request};
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test]
async fn google_http_deletion_requires_repeated_confirmation_then_commits_and_clears_authority(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let current = f.signin().await;
    let a = f.start(DELETE, &current).await;
    let query = f.fresh(&a).await;
    let cookie = format!("{}; {current}", a.cookie);
    let r = f
        .send(
            Request::builder()
                .uri(format!("/google/callback?{query}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status(), 200);
    assert!(text(r).await.contains("data-flow=\"delete\""));
    assert_eq!(f.facts().await, (1, 1, 1, 1, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    let r = f
        .post(
            DELETE,
            "finish",
            json!({"confirmation":"yes","query":query}),
            &cookie,
        )
        .await;
    assert_eq!(r.status(), 400);
    no_session(&r);
    let r = f
        .post(
            DELETE,
            "finish",
            json!({"confirmation":"delete my account","query":query}),
            &cookie,
        )
        .await;
    assert_eq!(r.status(), 204);
    assert!(
        r.headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("__Host-auth-session=;"))
    );
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
    assert_eq!(
        f.send(
            Request::builder()
                .uri("/v1/session")
                .header("cookie", &current)
                .body(Body::empty())
                .unwrap()
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        f.post(
            DELETE,
            "finish",
            json!({"confirmation":"delete my account","query":query}),
            &cookie
        )
        .await
        .status(),
        401
    );
    let fresh = f.start(ROOT, "").await;
    let query = f.fresh(&fresh).await;
    let r = f
        .post(ROOT, "finish", json!({"query":query}), &fresh.cookie)
        .await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    assert_eq!(
        f.facts().await,
        (0, 0, 0, 2, 0),
        "Google sign-in cannot bypass deleted-subject cooldown"
    );
}

#[sqlx::test]
async fn google_http_missing_malformed_and_old_signed_time_never_authorize_deletion(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let current = f.signin().await;
    for (attributes, status) in [
        (json!({}), 503),
        (json!({"auth_time":null}), 401),
        (
            json!({"auth_time":f.now().await-i64::try_from(MAX_OIDC_DELETION_AUTH_AGE_SECONDS).unwrap()-1}),
            401,
        ),
    ] {
        let before = f.provider.signed.load(Ordering::SeqCst);
        let a = f.start(DELETE, &current).await;
        let query = f.issue(&a, attributes).await;
        let r = f
            .post(
                DELETE,
                "finish",
                json!({"confirmation":"delete my account","query":query}),
                &format!("{}; {current}", a.cookie),
            )
            .await;
        assert_eq!(r.status().as_u16(), status);
        no_session(&r);
        assert_eq!(
            f.provider.signed.load(Ordering::SeqCst),
            before + 1,
            "actual signed time failure, not infrastructure rejection"
        );
        assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    }
    let a = f.start(DELETE, &current).await;
    let query = f.fresh(&a).await;
    assert_eq!(
        f.post(
            DELETE,
            "finish",
            json!({"confirmation":"delete my account","query":query}),
            &format!("{}; {current}", a.cookie)
        )
        .await
        .status(),
        204
    );
}

#[sqlx::test]
async fn google_http_deletion_retains_exact_subject_and_initiating_session_without_affecting_another_owner(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let first = f.signin().await;
    let other = f.start(ROOT, "").await;
    let query = f
        .issue(
            &other,
            json!({"sub":"second-google-owner","auth_time":f.now().await}),
        )
        .await;
    let r = f
        .post(ROOT, "finish", json!({"query":query}), &other.cookie)
        .await;
    assert_eq!(r.status(), 204);
    let second = session(&r);
    let a = f.start(DELETE, &first).await;
    let query = f.fresh(&a).await;
    let before = f.provider.posts.load(Ordering::SeqCst);
    let r = f
        .post(
            DELETE,
            "finish",
            json!({"confirmation":"delete my account","query":query}),
            &format!("{}; {second}", a.cookie),
        )
        .await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), before);
    assert_eq!(f.facts().await, (2, 2, 2, 2, 1));
    let r = f
        .post(
            DELETE,
            "finish",
            json!({"confirmation":"delete my account","query":query}),
            &format!("{}; {first}", a.cookie),
        )
        .await;
    assert_eq!(r.status(), 204);
    assert_eq!(f.facts().await, (1, 1, 1, 3, 0));
    let a = f.start(DELETE, &second).await;
    let wrong_subject = f.fresh(&a).await;
    let r = f
        .post(
            DELETE,
            "finish",
            json!({"confirmation":"delete my account","query":wrong_subject}),
            &format!("{}; {second}", a.cookie),
        )
        .await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    assert_eq!(f.facts().await, (1, 1, 1, 3, 0));
    assert_eq!(
        f.send(
            Request::builder()
                .uri("/v1/session")
                .header("cookie", second)
                .body(Body::empty())
                .unwrap()
        )
        .await
        .status(),
        200
    );
}
