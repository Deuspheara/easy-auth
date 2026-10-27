use super::setup::*;

#[sqlx::test]
async fn both_http_links_retain_original_session_and_unlink_only_owned_target(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (owner, session) = f.owner("owner@owned.example").await;
    let (_, other) = f.owner("other@owned.example").await;
    for provider in ["google", "apple"] {
        let a = f.start(provider, owner, &session).await;
        let raw = f.issue(provider, &a, "same-untrusted-profile").await;
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_sessions")
            .fetch_one(&f.pool)
            .await
            .unwrap();
        let r = f.finish(provider, &a, &raw).await;
        assert_eq!(r.status(), 204);
        no_session(&r);
        assert_eq!(r.headers().get_all("set-cookie").iter().count(), 4);
        let after: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_sessions")
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            body(f.get("/v1/session", &session).await).await["id"],
            owner.to_string()
        );
    }
    let page = f.inventory(&session).await;
    assert_eq!(page["providers"].as_array().unwrap().len(), 2);
    assert!(
        f.inventory(&other).await["providers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let identity = &page["providers"][0]["id"];
    let r = f
        .post(
            "/v1/account/providers/oidc/unlink",
            json!({"expected_owner":owner,
        "identity":identity,"confirmation":"unlink this account"}),
            &other,
        )
        .await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    let r = f
        .post(
            "/v1/account/providers/oidc/unlink",
            json!({"expected_owner":owner,
        "identity":identity,"confirmation":"unlink this account"}),
            &session,
        )
        .await;
    assert_eq!(r.status(), 204);
    no_session(&r);
    assert_eq!(
        f.inventory(&session).await["providers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[sqlx::test]
async fn linked_google_signin_resolves_owner_but_cannot_unlink_current_source(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (owner, session) = f.owner("owner@owned.example").await;
    let a = f.start("google", owner, &session).await;
    let raw = f.issue("google", &a, "retained-google").await;
    assert_eq!(f.finish("google", &a, &raw).await.status(), 204);
    let r = f.post("/v1/google/sign-in/start", json!({}), "").await;
    assert_eq!(r.status(), 200);
    let cookie = cookies(&r);
    let a = Attempt {
        cookie,
        url: url::Url::parse(body(r).await["authorization_url"].as_str().unwrap()).unwrap(),
    };
    let raw = f.issue("google", &a, "retained-google").await;
    let r = f
        .post("/v1/google/sign-in/finish", json!({"query":raw}), &a.cookie)
        .await;
    assert_eq!(r.status(), 204);
    let linked_session = crate::support::cookie(&r, "__Host-auth-session=");
    assert_eq!(
        body(f.get("/v1/session", &linked_session).await).await["id"],
        owner.to_string()
    );
    let page = f.inventory(&linked_session).await;
    let r = f
        .post(
            "/v1/account/providers/oidc/unlink",
            json!({"expected_owner":owner,
        "identity":page["providers"][0]["id"],"confirmation":"unlink this account"}),
            &linked_session,
        )
        .await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    let r = f
        .post(
            "/v1/account/providers/oidc/unlink",
            json!({"expected_owner":owner,
        "identity":page["providers"][0]["id"],"confirmation":"unlink this account"}),
            &session,
        )
        .await;
    assert_eq!(r.status(), 204);
    assert_eq!(f.get("/v1/session", &linked_session).await.status(), 401);
    assert_eq!(f.get("/v1/session", &session).await.status(), 200);
}

#[sqlx::test]
async fn concurrent_http_finishes_link_once_without_session_replacement(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (owner, session) = f.owner("owner@owned.example").await;
    let a = f.start("apple", owner, &session).await;
    let raw = f.issue("apple", &a, "race").await;
    let (left, right) = tokio::join!(f.finish("apple", &a, &raw), f.finish("apple", &a, &raw));
    let mut statuses = [left.status().as_u16(), right.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [204, 401]);
    no_session(&left);
    no_session(&right);
    assert_eq!(
        f.inventory(&session).await["providers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
