use super::*;
use auth_core::{IssuerTokenError, Repository};

#[sqlx::test]
async fn explicit_offline_grant_survives_cookie_idle_and_freshness_without_extending_cookie_or_authentication(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 50 seconds' WHERE realm_id=$1")
        .bind(f.base.authority.realm()).execute(&f.base.pool).await.unwrap();
    let code = f.code().await;
    let initial = f.exchange(&code).await.unwrap();
    sqlx::query("UPDATE auth_sessions SET last_seen_at=clock_timestamp()-interval '31 minutes' WHERE realm_id=$1")
        .bind(f.base.authority.realm()).execute(&f.base.pool).await.unwrap();
    let times:(i64,i64,i64)=sqlx::query_as("SELECT (extract(epoch FROM authenticated_at)*1000000)::bigint,(extract(epoch FROM last_seen_at)*1000000)::bigint,(extract(epoch FROM expires_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1")
        .bind(f.base.authority.realm()).fetch_one(&f.base.pool).await.unwrap();
    // Actual bounded elapsed time, not an altered signed proof or a new source.
    tokio::time::sleep(std::time::Duration::from_secs(11)).await;
    assert!(
        f.base
            .store
            .authenticate(f.base.authority.realm(), f.base.current.verifier())
            .await
            .is_err()
    );
    let _rotated = f
        .refresher()
        .refresh(
            &f.authentication(),
            &initial.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    let after:(i64,i64,i64)=sqlx::query_as("SELECT (extract(epoch FROM authenticated_at)*1000000)::bigint,(extract(epoch FROM last_seen_at)*1000000)::bigint,(extract(epoch FROM expires_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1")
        .bind(f.base.authority.realm()).fetch_one(&f.base.pool).await.unwrap();
    assert_eq!(after, times);
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT authenticated_at_us=$2 FROM auth_issuer_native_families WHERE realm_id=$1"
        )
        .bind(f.base.authority.realm())
        .bind(times.0)
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
}

#[sqlx::test]
async fn policy_client_owner_method_session_and_namespace_changes_cannot_refresh_old_grant(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let initial = f.exchange(&code).await.unwrap();
    let refresh = f.refresher();
    let auth = f.authentication();
    let token = initial.refresh_token().into();
    f.base
        .store
        .disable_issuer_signing(&f.base.authority)
        .await
        .unwrap();
    assert!(matches!(
        refresh.refresh(&auth, &token, "127.0.0.1").await,
        Err(IssuerTokenError::Unavailable)
    ));
    let revision: Uuid =
        sqlx::query_scalar("SELECT revision FROM auth_issuer_key_sets WHERE realm_id=$1")
            .bind(f.base.authority.realm())
            .fetch_one(&f.base.pool)
            .await
            .unwrap();
    f.base
        .store
        .enable_issuer_signing(&f.base.authority, revision)
        .await
        .unwrap();
    sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2").bind(f.base.authority.realm()).bind(f.base.owner).execute(&f.base.pool).await.unwrap();
    assert!(matches!(
        refresh.refresh(&auth, &token, "127.0.0.1").await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert_eq!(f.facts().await, (1, 1, 1, 1, 1));
    refresh.revoke(&auth, &token, "127.0.0.1").await.unwrap();
    let other = Fixture::new(f.base.pool.clone()).await;
    let code = other.code().await;
    let issued = other.exchange(&code).await.unwrap();
    let _current = other
        .base
        .store
        .configure_issuer_client(other.policy.client())
        .await
        .unwrap();
    assert!(matches!(
        other
            .refresher()
            .refresh(
                &other.authentication(),
                &issued.refresh_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert_eq!(other.facts().await, (1, 1, 1, 1, 1));
}

#[sqlx::test]
async fn changed_native_policy_or_shortened_original_source_cannot_widen_family_authority(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let initial = f.exchange(&code).await.unwrap();
    let _current = f
        .base
        .store
        .configure_issuer_native_refresh_policy(&f.policy)
        .await
        .unwrap();
    assert!(matches!(
        f.refresher()
            .refresh(
                &f.authentication(),
                &initial.refresh_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    let other = Fixture::new(f.base.pool.clone()).await;
    let code = other.code().await;
    let issued = other.exchange(&code).await.unwrap();
    sqlx::query(
        "UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE realm_id=$1",
    )
    .bind(other.base.authority.realm())
    .execute(&other.base.pool)
    .await
    .unwrap();
    assert!(matches!(
        other
            .refresher()
            .refresh(
                &other.authentication(),
                &issued.refresh_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert_eq!(f.facts().await, (1, 1, 1, 1, 1));
    assert_eq!(other.facts().await, (1, 1, 1, 1, 1));
}
