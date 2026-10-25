use super::setup::*;
use sqlx::PgPool;

#[sqlx::test]
async fn apple_verified_completion_commits_once_and_ignores_unsigned_names(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let raw = f
        .issue(
            &a,
            json!({"email":"relay@privaterelay.appleid.com","email_verified":"true"}),
            Some(r#"{"name":{"firstName":"UNSIGNED"},"email":"attacker@example.com"}"#),
        )
        .await;
    let r = f.post("finish", json!({"response":raw}), &a.cookie).await;
    assert_eq!(r.status(), 204);
    let current = session(&r);
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    let r = f
        .send(
            Request::builder()
                .uri("/v1/session")
                .header("cookie", current)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status(), 200);
    let output = text(r).await;
    assert!(
        !output.contains("UNSIGNED") && !output.contains("relay@") && !output.contains("attacker@")
    );
    let replay = f.post("finish", json!({"response":raw}), &a.cookie).await;
    assert_eq!(replay.status(), 401);
    no_session(&replay);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    let b = f.start().await;
    let raw = f.issue(&b, json!({}), None).await;
    assert_eq!(
        f.post("finish", json!({"response":raw}), &b.cookie)
            .await
            .status(),
        204
    );
    assert_eq!(f.facts().await, (1, 1, 2, 2, 0));
}

#[sqlx::test]
async fn apple_stale_return_and_cancel_cannot_clear_newer_operation(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let stale = f.start().await;
    let raw = f.issue(&stale, json!({}), None).await;
    assert_eq!(
        f.post(
            "cancel",
            json!({"state":stale.field("state")}),
            &stale.cookie
        )
        .await
        .status(),
        204
    );
    let current = f.start().await;
    for (action, body) in [
        ("finish", json!({"response":raw})),
        ("cancel", json!({"state":stale.field("state")})),
    ] {
        let r = f.post(action, body, &current.cookie).await;
        assert_eq!(r.status(), 401);
        no_session(&r);
        assert!(r.headers().get_all("set-cookie").iter().next().is_none());
    }
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    let raw = f.issue(&current, json!({}), None).await;
    assert_eq!(
        f.post("finish", json!({"response":raw}), &current.cookie)
            .await
            .status(),
        204
    );
}

#[sqlx::test]
async fn apple_wrong_browser_realm_and_signed_nonce_never_commit(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let other = Fixture::with_origin(pool, "https://other.example").await;
    let a = f.start().await;
    let b = f.start().await;
    let raw = f.issue(&a, json!({}), None).await;
    for (fixture, cookie) in [
        (&f, ""),
        (&f, b.cookie.as_str()),
        (&other, a.cookie.as_str()),
    ] {
        let r = fixture
            .post("finish", json!({"response":raw}), cookie)
            .await;
        assert_eq!(r.status(), 401);
        no_session(&r);
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(other.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(
        f.post("finish", json!({"response":raw}), &a.cookie)
            .await
            .status(),
        204
    );
    let raw = f
        .issue(&b, json!({"nonce":"wrong-signed-nonce"}), None)
        .await;
    let r = f.post("finish", json!({"response":raw}), &b.cookie).await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    assert_eq!(r.headers().get_all("set-cookie").iter().count(), 4);
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
}

#[sqlx::test]
async fn apple_denial_and_explicit_cancel_retain_existing_session(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let denial = format!("state={}&error=user_cancelled_authorize", a.field("state"));
    let r = f
        .post("finish", json!({"response":denial}), &a.cookie)
        .await;
    assert_eq!(r.status(), 401);
    assert!(!text(r).await.contains("private-detail"));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    let session_cookie = f.signin().await;
    let a = f.start().await;
    let r = f
        .post(
            "cancel",
            json!({"state":a.field("state")}),
            &format!("{}; {session_cookie}", a.cookie),
        )
        .await;
    assert_eq!(r.status(), 204);
    no_session(&r);
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert_eq!(
        f.send(
            Request::builder()
                .uri("/v1/session")
                .header("cookie", session_cookie)
                .body(Body::empty())
                .unwrap()
        )
        .await
        .status(),
        200
    );
}

#[sqlx::test]
async fn apple_concurrent_finish_has_one_committed_winner(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let raw = f.issue(&a, json!({}), None).await;
    let (left, right) = tokio::join!(
        f.post("finish", json!({"response":raw}), &a.cookie),
        f.post("finish", json!({"response":raw}), &a.cookie)
    );
    let mut statuses = [left.status().as_u16(), right.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [204, 401]);
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
}
