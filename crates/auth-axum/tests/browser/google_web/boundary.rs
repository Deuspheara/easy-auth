use super::setup::*;
use crate::support::post;
use axum::{
    body::Body,
    http::{Request, header},
};
use easy_auth_axum::{BrowserConfig, experimental_google_web_router};
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test]
async fn google_http_all_mutations_require_exact_origin_closed_query_and_json_input(pool: PgPool) {
    let f = Fixture::new(pool).await;
    for root in [ROOT, DELETE] {
        for action in ["start", "finish", "cancel"] {
            let path = format!("{root}/{action}");
            for origin in [None, Some("null"), Some("https://foreign.example")] {
                let r = f.send(post(&path, "{}", None, origin)).await;
                assert_eq!(r.status(), 403);
                no_session(&r);
            }
            let mut request = post(&path, "{}", None, Some(ORIGIN));
            request
                .headers_mut()
                .append(header::ORIGIN, ORIGIN.parse().unwrap());
            assert_eq!(f.send(request).await.status(), 403);
            let r = f
                .send(post(
                    &format!("{path}?authority=private"),
                    "{}",
                    None,
                    Some(ORIGIN),
                ))
                .await;
            assert_eq!(r.status(), 400);
            assert!(!text(r).await.contains("private"));
            let r = f
                .send(
                    Request::builder()
                        .method("POST")
                        .uri(&path)
                        .header("origin", ORIGIN)
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await;
            assert_eq!(r.status(), 415);
        }
    }
    for root in [ROOT, DELETE] {
        for action in ["start", "finish", "cancel"] {
            let r=f.post(root,action,json!({"query":"private","owner":"injected","confirmation":"delete my account"}),"").await;
            assert_eq!(r.status(), 400);
            assert!(!text(r).await.contains("private"));
        }
    }
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(f.provider.document_gets.load(Ordering::SeqCst), 0);
}

#[sqlx::test]
async fn google_http_body_and_raw_callback_bounds_cannot_overwrite_pending_proof(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start(ROOT, "").await;
    assert_eq!(
        f.post(ROOT, "start", json!({}), &a.cookie).await.status(),
        401
    );
    let r = f
        .post(
            ROOT,
            "finish",
            json!({"query":"a".repeat(64*1024)}),
            &a.cookie,
        )
        .await;
    assert_eq!(r.status(), 413);
    no_session(&r);
    let r = f
        .post(ROOT, "finish", json!({"query":"a".repeat(8193)}), &a.cookie)
        .await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    assert!(r.headers().get_all("set-cookie").iter().next().is_none());
    for name in ["browser", "state", "nonce", "pkce"] {
        let duplicate = format!("{}; __Host-auth-google-signin-{name}=invalid", a.cookie);
        assert_eq!(
            f.post(ROOT, "start", json!({}), &duplicate).await.status(),
            401
        );
        assert_eq!(
            f.post(ROOT, "finish", json!({"query":"private"}), &duplicate)
                .await
                .status(),
            401
        );
    }
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    let query = f.fresh(&a).await;
    assert_eq!(
        f.post(ROOT, "finish", json!({"query":query}), &a.cookie)
            .await
            .status(),
        204
    );
}

#[sqlx::test]
async fn google_http_https_exact_callback_and_realm_are_composition_requirements(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let other = Fixture::with_origin(pool, "https://other.example").await;
    for browser in [
        BrowserConfig::new("http://localhost:12345", true).unwrap(),
        BrowserConfig::new("https://other.example", false).unwrap(),
    ] {
        assert!(
            experimental_google_web_router(f.auth.clone(), browser, f.services.clone()).is_err()
        );
    }
    assert!(
        experimental_google_web_router(
            other.auth.clone(),
            BrowserConfig::new(ORIGIN, false).unwrap(),
            f.services.clone()
        )
        .is_err()
    );
    let r = f
        .send(
            Request::builder()
                .uri("/google/sign-in")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    for name in [
        "cache-control",
        "referrer-policy",
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
    ] {
        assert!(r.headers().contains_key(name));
    }
    no_session(&r);
    assert_eq!(f.provider.document_gets.load(Ordering::SeqCst), 0);
}

#[sqlx::test]
async fn google_http_logout_clears_both_google_proof_sets_without_other_session_grants(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let current = f.signin().await;
    let sign_in = f.start(ROOT, "").await;
    let deletion = f.start(DELETE, &current).await;
    let cookie = format!("{}; {}; {current}", sign_in.cookie, deletion.cookie);
    let r = f.post("/v1", "logout", json!({}), &cookie).await;
    assert_eq!(r.status(), 204);
    let cleared: Vec<_> = r
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .filter(|v| v.starts_with("__Host-auth-google-"))
        .collect();
    assert_eq!(cleared.len(), 8);
    assert!(
        cleared
            .iter()
            .all(|v| v.contains("=;") && v.contains("Max-Age=0"))
    );
    let r=f.post(DELETE,"finish",json!({"confirmation":"delete my account","query":callback(&deletion,None,Some("access_denied"))}),&format!("{}; {current}",deletion.cookie)).await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
}
