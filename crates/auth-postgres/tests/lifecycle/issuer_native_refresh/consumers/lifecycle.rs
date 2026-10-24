use super::*;

#[sqlx::test]
async fn actual_basic_authentication_precedes_unknown_inactive_and_active_token_results(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let c = Consumer::new(&f).await;
    c.enable(&f).await;
    let token = issued(&f).await;
    for presented in [
        Secret::generate().unwrap(),
        Secret::parse(token.access_token().expose().into()).unwrap(),
    ] {
        for auth in [
            IssuerClientAuthentication::public(c.policy.consumer().client()).unwrap(),
            IssuerClientAuthentication::basic(
                c.policy.consumer().client(),
                &Secret::generate().unwrap(),
            )
            .unwrap(),
            f.authentication(),
        ] {
            assert!(matches!(
                c.service(&f)
                    .introspect_access(&auth, &(&presented).into(), "127.0.0.1")
                    .await,
                Err(IssuerTokenError::InvalidClient)
            ));
        }
    }
    assert!(
        c.inspect(&f, &Secret::generate().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        c.inspect(&f, token.refresh_token())
            .await
            .unwrap()
            .is_none()
    );
    let active = c.inspect(&f, token.access_token()).await.unwrap().unwrap();
    assert_eq!(active.access().client(), f.policy.client().client());
    assert_eq!(active.access().issuer(), f.base.authority.issuer());
    assert_ne!(active.access().subject(), f.base.owner);
    assert!(
        f.base
            .store
            .authenticate(f.base.authority.realm(), token.access_token().verifier())
            .await
            .is_err()
    );
}

#[sqlx::test]
async fn native_inspection_preserves_cookie_times_and_original_family_without_code_freshness(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let c = Consumer::new(&f).await;
    c.enable(&f).await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 50 seconds' WHERE realm_id=$1").bind(f.base.authority.realm()).execute(&f.base.pool).await.unwrap();
    let token = issued(&f).await;
    sqlx::query("UPDATE auth_sessions SET last_seen_at=clock_timestamp()-interval '31 minutes' WHERE realm_id=$1").bind(f.base.authority.realm()).execute(&f.base.pool).await.unwrap();
    let before: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(s) FROM auth_sessions s WHERE realm_id=$1")
            .bind(f.base.authority.realm())
            .fetch_one(&f.base.pool)
            .await
            .unwrap();
    assert!(
        f.base
            .store
            .authenticate(f.base.authority.realm(), f.base.current.verifier())
            .await
            .is_err()
    );
    // Let the original genuine code/freshness bound elapse; the explicit family
    // keeps its separate original absolute authority and never extends the cookie.
    tokio::time::sleep(std::time::Duration::from_secs(11)).await;
    let next = f
        .refresher()
        .refresh(
            &f.authentication(),
            &token.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
    assert!(c.inspect(&f, next.access_token()).await.unwrap().is_some());
    let after: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(s) FROM auth_sessions s WHERE realm_id=$1")
            .bind(f.base.authority.realm())
            .fetch_one(&f.base.pool)
            .await
            .unwrap();
    assert_eq!(after, before);
    assert!(matches!(
        f.refresher()
            .refresh(
                &f.authentication(),
                &token.refresh_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    for access in [token.access_token(), next.access_token()] {
        assert!(c.inspect(&f, access).await.unwrap().is_none());
    }
}

#[sqlx::test]
async fn current_key_namespace_and_original_owner_session_remain_required(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let c = Consumer::new(&f).await;
    c.enable(&f).await;
    let token = issued(&f).await;
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_some());
    f.base
        .store
        .disable_issuer_signing(&f.base.authority)
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
    let revision = f
        .base
        .store
        .activate_issuer_key(&f.base.authority, f.base.key.id())
        .await
        .unwrap();
    f.base
        .store
        .enable_issuer_signing(&f.base.authority, revision)
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_some());
    f.base
        .store
        .revoke_all_sessions(f.base.authority.realm(), f.base.current.verifier())
        .await
        .unwrap();
    assert!(c.inspect(&f, token.access_token()).await.unwrap().is_none());
}
