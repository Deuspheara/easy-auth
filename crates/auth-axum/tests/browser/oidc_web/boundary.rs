use super::setup::*;
use axum::{
    body::Body,
    http::{Request, header},
};
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test]
async fn start_rejects_any_ambient_session_cookie_and_pending_proof(pool: PgPool) {
    let f = Fixture::new(pool).await;
    for cookie in [
        "__Host-auth-session=invalid",
        "__Host-auth-session=",
        "__Host-auth-session",
        "__Host-auth-session=a; __Host-auth-session=b",
    ] {
        let r = f.post("start", json!({}), cookie).await;
        assert_eq!(r.status(), 401);
        no_session(&r);
        assert_eq!(f.facts().await, (0, 0, 0, 0));
    }
    let a = f.start().await;
    assert_eq!(f.post("start", json!({}), &a.cookie).await.status(), 401);
    assert_eq!(f.facts().await, (0, 0, 0, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
}

#[sqlx::test]
async fn all_mutating_routes_enforce_origin_closed_json_query_and_bounds(pool: PgPool) {
    let f = Fixture::new(pool).await;
    for action in ["start", "finish", "cancel"] {
        let path = format!("{ROOT}/{action}");
        for origin in [None, Some("https://other.example"), Some("null")] {
            assert_eq!(
                f.send(crate::support::post(&path, "{}", None, origin))
                    .await
                    .status(),
                403
            );
        }
        let mut request = crate::support::post(&path, "{}", None, Some(ORIGIN));
        request
            .headers_mut()
            .append(header::ORIGIN, ORIGIN.parse().unwrap());
        assert_eq!(f.send(request).await.status(), 403);
        for body in [
            r#"{"unexpected":"rejected"}"#,
            r#"{"state":"a","state":"b","code":"c"}"#,
            "[",
        ] {
            assert_eq!(
                f.send(crate::support::post(&path, body, None, Some(ORIGIN)))
                    .await
                    .status(),
                400
            );
        }
        assert_eq!(
            f.send(crate::support::post(
                &format!("{path}?unknown=1"),
                "{}",
                None,
                Some(ORIGIN)
            ))
            .await
            .status(),
            400
        );
        assert_eq!(
            f.send(crate::support::post(
                &path,
                &"a".repeat(8193),
                None,
                Some(ORIGIN)
            ))
            .await
            .status(),
            413
        );
        assert_eq!(
            f.send(
                Request::builder()
                    .method("POST")
                    .uri(&path)
                    .header(header::ORIGIN, ORIGIN)
                    .body(Body::from("{}"))
                    .unwrap()
            )
            .await
            .status(),
            415
        );
    }
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
}

#[sqlx::test]
async fn session_arriving_after_start_prevents_consumption_and_switching(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let original = f.start().await;
    let r = f.post("finish", original.callback, &original.cookie).await;
    assert_eq!(r.status(), 204);
    let current = session(&r);
    let a = f.start().await;
    let r = f
        .post(
            "finish",
            a.callback.clone(),
            &format!("{}; {}", a.cookie, current),
        )
        .await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    cleared(&r);
    assert_eq!(f.facts().await, (1, 1, 1, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    // Cancellation is still available after the session transition, without logout.
    let r = f
        .post("cancel", json!({}), &format!("{}; {}", a.cookie, current))
        .await;
    assert_eq!(r.status(), 204);
    no_session(&r);
    assert_eq!(f.facts().await, (1, 1, 1, 0));
}

#[sqlx::test]
async fn overlapping_starts_remain_distinct_and_cancel_independently(pool: PgPool) {
    let f = Fixture::new(pool).await;
    // This case isolates concurrent proof namespaces from cold-discovery
    // admission, which deliberately fails prompt contenders with 429. Exercise
    // that boundary separately rather than depending on fixture/runner timing.
    let warm = f.start().await;
    assert_eq!(
        f.post("cancel", json!({}), &warm.cookie).await.status(),
        204
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    let (a, b) = tokio::join!(
        f.post("start", json!({}), ""),
        f.post("start", json!({}), "")
    );
    assert_eq!(a.status(), 200);
    assert_eq!(b.status(), 200);
    no_session(&a);
    no_session(&b);
    let a = cookies(&a);
    let b = cookies(&b);
    assert!(a != b, "distinct starts must not share protected proof");
    assert_eq!(f.facts().await, (0, 0, 0, 2));
    assert_eq!(f.post("cancel", json!({}), &a).await.status(), 204);
    assert_eq!(f.facts().await, (0, 0, 0, 1));
    assert_eq!(f.post("cancel", json!({}), &b).await.status(), 204);
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
}

#[sqlx::test]
async fn composition_requires_https_exact_callback_origin_and_realm(pool: PgPool) {
    use auth_core::{Auth, Error};
    use easy_auth_axum::{BrowserConfig, oidc_web_router};
    let f = Fixture::new(pool).await;
    for browser in [
        BrowserConfig::new("http://localhost", true).unwrap(),
        BrowserConfig::new("https://other.example", false).unwrap(),
    ] {
        assert!(matches!(
            oidc_web_router(f.auth.clone(), browser, f.services.clone()),
            Err(Error::InvalidInput)
        ));
    }
    let foreign = Auth::new(
        uuid::Uuid::new_v4(),
        f.store.clone(),
        std::sync::Arc::new(crate::support::Mail::default()),
    );
    assert!(matches!(
        oidc_web_router(
            foreign,
            BrowserConfig::new(ORIGIN, false).unwrap(),
            f.services.clone()
        ),
        Err(Error::InvalidInput)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0));
}

// Peer address is a committed abuse-admission dimension, not an IP-bound identity.
// Populate only exhausted quota metadata; all usable proof still comes from start.
#[sqlx::test]
async fn trusted_peer_admission_cannot_be_bypassed_with_forwarded_headers(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    sqlx::query("INSERT INTO auth_oauth_admission(realm_id,dimension,key_hash,window_id,attempts) SELECT $1,'consume_source',sha256(sha256(convert_to('192.0.2.9','UTF8'))),n,80 FROM generate_series(floor(extract(epoch FROM clock_timestamp())/600)::bigint,floor(extract(epoch FROM clock_timestamp())/600)::bigint+1) n")
        .bind(f.policy.configuration().realm()).execute(&f.pool).await.expect("test infrastructure: exhaust actual peer admission only");
    let make_request =
        || {
            let mut request = crate::support::post(
                &format!("{ROOT}/finish"),
                &a.callback.to_string(),
                Some(&a.cookie),
                Some(ORIGIN),
            );
            request
                .headers_mut()
                .insert("x-forwarded-for", "198.51.100.9".parse().unwrap());
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                std::net::SocketAddr::from(([192, 0, 2, 9], 443)),
            ));
            request
        };
    let r = f.send(make_request()).await;
    assert_eq!(r.status(), 429);
    no_session(&r);
    cleared(&r);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.facts().await, (0, 0, 0, 1));
    sqlx::query("DELETE FROM auth_oauth_admission WHERE realm_id=$1 AND dimension='consume_source' AND key_hash=sha256(sha256(convert_to('192.0.2.9','UTF8')))")
        .bind(f.policy.configuration().realm()).execute(&f.pool).await.expect("test infrastructure: release only owned peer quota");
    let r = f.send(make_request()).await;
    assert_eq!(r.status(), 204);
    let _ = session(&r);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (1, 1, 1, 0));
}
