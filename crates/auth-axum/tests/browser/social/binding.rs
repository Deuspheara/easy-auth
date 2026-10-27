use super::setup::*;

#[sqlx::test]
async fn link_starts_require_exact_origin_closed_confirmation_current_owner_and_no_pending_proof(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (owner, session) = f.owner("owner@owned.example").await;
    for provider in ["google", "apple"] {
        let path = format!("/v1/account/{provider}-link/start");
        let valid = json!({"expected_owner":owner,"confirmation":"link this account"});
        assert_eq!(f.post(&path, valid.clone(), "").await.status(), 401);
        assert_eq!(
            f.post(
                &path,
                json!({"expected_owner":Uuid::new_v4(),"confirmation":"link this account"}),
                &session
            )
            .await
            .status(),
            401
        );
        assert_eq!(
            f.post(
                &path,
                json!({"expected_owner":owner,"confirmation":"yes"}),
                &session
            )
            .await
            .status(),
            400
        );
        assert_eq!(f.post(&path, json!({"expected_owner":owner,"confirmation":"link this account","subject":"injected"}), &session).await.status(),400);
        assert_eq!(
            f.post(&format!("{path}?unknown=1"), valid.clone(), &session)
                .await
                .status(),
            400
        );
        for origin in [None, Some("https://other.example")] {
            let r = f
                .send(crate::support::post(
                    &path,
                    &valid.to_string(),
                    Some(&session),
                    origin,
                ))
                .await;
            assert_eq!(r.status(), 403);
            assert!(r.headers().get_all("set-cookie").iter().next().is_none());
        }
        let a = f.start(provider, owner, &session).await;
        assert_eq!(f.post(&path, valid, &a.cookie).await.status(), 401);
    }
}

#[sqlx::test]
async fn neither_changed_owner_nor_another_fresh_device_can_finish_original_link(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (owner, session) = f.owner("owner@owned.example").await;
    let (_, device) = f.owner("owner@owned.example").await;
    let (_, other) = f.owner("other@owned.example").await;
    for provider in ["google", "apple"] {
        let a = f.start(provider, owner, &session).await;
        let raw = f.issue(provider, &a, "bound").await;
        for replacement in [&device, &other] {
            let changed = Attempt {
                cookie: a.cookie.replace(&session, replacement),
                url: a.url.clone(),
            };
            let r = f.finish(provider, &changed, &raw).await;
            assert_eq!(r.status(), 401);
            no_session(&r);
        }
        // Rejections of the initiating binding do not turn another device into the owner.
        assert!(
            f.inventory(&other).await["providers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

#[sqlx::test]
async fn stale_callback_and_cancel_cannot_clear_newer_private_link_cookies(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (owner, session) = f.owner("owner@owned.example").await;
    for provider in ["google", "apple"] {
        let a = f.start(provider, owner, &session).await;
        let raw = f.issue(provider, &a, "bound").await;
        let wrong = Secret::generate().unwrap();
        let changed = raw.replace(&a.field("state"), wrong.expose());
        let r = f.finish(provider, &a, &changed).await;
        assert_eq!(r.status(), 401);
        assert!(r.headers().get_all("set-cookie").iter().next().is_none());
        let r = f
            .post(
                &format!("/v1/account/{provider}-link/cancel"),
                json!({"state":wrong.expose()}),
                &a.cookie,
            )
            .await;
        assert_eq!(r.status(), 401);
        assert!(r.headers().get_all("set-cookie").iter().next().is_none());
        assert_eq!(f.finish(provider, &a, &raw).await.status(), 204);
    }
}

#[sqlx::test]
async fn sign_in_cannot_consume_link_and_owned_cancel_retains_current_session(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (owner, session) = f.owner("owner@owned.example").await;
    for provider in ["google", "apple"] {
        let a = f.start(provider, owner, &session).await;
        let raw = f.issue(provider, &a, "bound").await;
        let key = if provider == "google" {
            "query"
        } else {
            "response"
        };
        let mut input = json!({});
        input[key] = json!(raw);
        let r = f
            .post(&format!("/v1/{provider}/sign-in/finish"), input, &a.cookie)
            .await;
        assert_eq!(r.status(), 401);
        no_session(&r);
        let r = f
            .post(
                &format!("/v1/account/{provider}-link/cancel"),
                json!({"state":a.field("state")}),
                &a.cookie,
            )
            .await;
        assert_eq!(r.status(), 204);
        no_session(&r);
        assert_eq!(r.headers().get_all("set-cookie").iter().count(), 4);
        assert_eq!(f.finish(provider, &a, &raw).await.status(), 401);
        assert_eq!(f.get("/v1/session", &session).await.status(), 200);
    }
}
