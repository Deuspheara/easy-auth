use super::*;
use auth_core::IssuerTokenError;

#[sqlx::test]
async fn either_owned_credential_can_revoke_entire_family_after_policy_and_session_disable(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let initial = f.exchange(&code).await.unwrap();
    let refresh = f.refresher();
    let auth = f.authentication();
    let next = refresh
        .refresh(&auth, &initial.refresh_token().into(), "127.0.0.1")
        .await
        .unwrap();
    f.base
        .store
        .disable_issuer_native_refresh_policy(f.policy.authority(), f.policy.client().client())
        .await
        .unwrap();
    sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1")
        .bind(f.base.authority.realm())
        .execute(&f.base.pool)
        .await
        .unwrap();
    refresh
        .revoke(&auth, &initial.access_token().into(), "127.0.0.1")
        .await
        .unwrap();
    let at: i64 = sqlx::query_scalar("SELECT revoked_at_us FROM auth_issuer_native_families")
        .fetch_one(&f.base.pool)
        .await
        .unwrap();
    refresh
        .revoke(&auth, &next.refresh_token().into(), "127.0.0.1")
        .await
        .unwrap();
    refresh
        .revoke(
            &auth,
            &auth_core::IssuerPresentedToken::parse("unknown opaque credential".into()).unwrap(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT revoked_at_us FROM auth_issuer_native_families")
            .fetch_one(&f.base.pool)
            .await
            .unwrap(),
        at
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT bool_and(revoked_at_us IS NOT NULL) FROM auth_issuer_access_tokens"
        )
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM auth_audit WHERE kind='issuer_native_revoked' AND issuer_credential_kind='access_token' AND actor_session_id IS NULL").fetch_one(&f.base.pool).await.unwrap(),1);
    assert!(matches!(
        refresh
            .refresh(&auth, &next.refresh_token().into(), "127.0.0.1")
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
}

#[sqlx::test]
async fn database_only_revoke_refresh_race_never_leaves_an_active_family_or_descendant(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let initial = f.exchange(&code).await.unwrap();
    let refresh = f.refresher();
    let auth = f.authentication();
    let token = initial.refresh_token().into();
    // Initial signature has already finished; these operations touch only DB state.
    let (rotated, revoked) = tokio::join!(
        refresh.refresh(&auth, &token, "127.0.0.1"),
        refresh.revoke(&auth, &token, "127.0.0.1")
    );
    revoked.unwrap();
    assert!(rotated.is_ok() || matches!(rotated, Err(IssuerTokenError::InvalidGrant)));
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT revoked_at_us IS NOT NULL FROM auth_issuer_native_families"
        )
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT bool_and(revoked_at_us IS NOT NULL) FROM auth_issuer_access_tokens"
        )
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
}
