use super::setup::*;
use crate::support::post;
use sqlx::PgPool;

#[sqlx::test]
async fn apple_authority_requires_exact_origin_closed_queries_and_json(pool: PgPool) {
    let f = Fixture::new(pool).await;
    for action in ["start", "finish", "cancel"] {
        let path = format!("{ROOT}/{action}");
        for origin in [
            None,
            Some("null"),
            Some(ISSUER),
            Some("https://foreign.example"),
        ] {
            assert_eq!(f.send(post(&path, "{}", None, origin)).await.status(), 403);
        }
        let mut duplicate = post(&path, "{}", None, Some(ORIGIN));
        duplicate
            .headers_mut()
            .append("origin", ORIGIN.parse().unwrap());
        assert_eq!(f.send(duplicate).await.status(), 403);
        assert_eq!(
            f.send(post(
                &format!("{path}?owner=private"),
                "{}",
                None,
                Some(ORIGIN)
            ))
            .await
            .status(),
            400
        );
        assert_eq!(
            f.post(action, json!({"owner":"private"}), "")
                .await
                .status(),
            400
        );
        assert_eq!(
            f.send(
                Request::builder()
                    .method("POST")
                    .uri(&path)
                    .header("origin", ORIGIN)
                    .body(Body::from("{}"))
                    .unwrap()
            )
            .await
            .status(),
            415
        );
    }
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
}

#[sqlx::test]
async fn apple_pending_proofs_are_lax_independent_and_cannot_be_overwritten(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let r = f.post("start", json!({}), "").await;
    assert_eq!(r.status(), 200);
    let proof = cookies(&r);
    let headers: Vec<_> = r
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(headers.len(), 4);
    for value in headers {
        assert!(
            value.starts_with("__Host-auth-apple-signin-")
                && value.contains("Secure")
                && value.contains("HttpOnly")
                && value.contains("SameSite=Lax")
                && value.contains("Path=/")
                && value.contains("Max-Age=300")
                && !value.contains("Domain=")
        );
    }
    assert_eq!(f.post("start", json!({}), &proof).await.status(), 401);
    for name in ["browser", "state", "nonce", "pkce"] {
        let duplicate = format!("{proof}; __Host-auth-apple-signin-{name}=invalid");
        let r = f
            .post("finish", json!({"response":"private"}), &duplicate)
            .await;
        assert_eq!(r.status(), 401);
        assert!(r.headers().get_all("set-cookie").iter().next().is_none());
    }
    let r = f
        .post("finish", json!({"response":"a".repeat(192*1024)}), &proof)
        .await;
    assert_eq!(r.status(), 413);
    no_session(&r);
    let r = f
        .post("finish", json!({"response":"a".repeat(32769)}), &proof)
        .await;
    assert_eq!(r.status(), 401);
    assert!(r.headers().get_all("set-cookie").iter().next().is_none());
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.post("cancel", json!({}), &proof).await.status(), 204);
}

#[sqlx::test]
async fn apple_ambient_sessions_cannot_be_replaced_and_logout_clears_proofs(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let session_cookie = f.signin().await;
    let a = f.start().await;
    let raw = f.issue(&a, json!({"sub":"other-subject"}), None).await;
    for session in [session_cookie.as_str(), "__Host-auth-session=invalid"] {
        assert_eq!(f.post("start", json!({}), session).await.status(), 401);
        let r = f
            .post(
                "finish",
                json!({"response":raw}),
                &format!("{}; {session}", a.cookie),
            )
            .await;
        assert_eq!(r.status(), 401);
        no_session(&r);
        assert!(r.headers().get_all("set-cookie").iter().next().is_none());
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    let r = f
        .send(post(
            "/v1/logout",
            "{}",
            Some(&format!("{}; {session_cookie}", a.cookie)),
            Some(ORIGIN),
        ))
        .await;
    assert_eq!(r.status(), 204);
    let cleared: Vec<_> = r
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .filter(|v| v.starts_with("__Host-auth-apple-"))
        .collect();
    assert_eq!(cleared.len(), 4);
    assert!(
        cleared
            .iter()
            .all(|v| v.contains("=;") && v.contains("Max-Age=0"))
    );
}
