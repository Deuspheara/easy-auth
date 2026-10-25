use super::*;
use auth_core::{IssuerTokenError, Repository};

#[sqlx::test]
async fn rotation_is_hash_only_one_use_and_retains_original_absolute_caps_without_touching_cookie_time(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let initial = f.exchange(&code).await.unwrap();
    let original:(i64,i64,i64,i64)=sqlx::query_as("SELECT f.expires_at_us,(extract(epoch FROM s.last_seen_at)*1000000)::bigint,(extract(epoch FROM s.authenticated_at)*1000000)::bigint,(extract(epoch FROM s.expires_at)*1000000)::bigint FROM auth_issuer_native_families f JOIN auth_sessions s ON (s.realm_id,s.id)=(f.realm_id,f.session_id)")
        .fetch_one(&f.base.pool).await.unwrap();
    let refresh = f.refresher();
    let first = refresh
        .refresh(
            &f.authentication(),
            &initial.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    let second = refresh
        .refresh(
            &f.authentication(),
            &first.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert!(first.expires_in() > 0 && first.expires_in() <= 300);
    assert!(first.refresh_expires_in() <= 3600);
    assert_ne!(
        first.refresh_token().verifier(),
        initial.refresh_token().verifier()
    );
    assert_ne!(
        second.refresh_token().verifier(),
        first.refresh_token().verifier()
    );
    assert!(!format!("{second:?}").contains(second.refresh_token().expose()));
    let after:(i64,i64,i64,i64)=sqlx::query_as("SELECT f.expires_at_us,(extract(epoch FROM s.last_seen_at)*1000000)::bigint,(extract(epoch FROM s.authenticated_at)*1000000)::bigint,(extract(epoch FROM s.expires_at)*1000000)::bigint FROM auth_issuer_native_families f JOIN auth_sessions s ON (s.realm_id,s.id)=(f.realm_id,f.session_id)")
        .fetch_one(&f.base.pool).await.unwrap();
    assert_eq!(after, original);
    let exact:bool=sqlx::query_scalar("SELECT f.generation=2 AND f.revoked_at_us IS NULL AND (SELECT count(*) FROM auth_issuer_native_refresh_tokens)=3 AND (SELECT count(*) FROM auth_issuer_native_refresh_tokens WHERE spent_at_us IS NULL)=1 AND (SELECT token_hash=$1 FROM auth_issuer_native_refresh_tokens WHERE generation=2) AND (SELECT access_hash=$2 FROM auth_issuer_access_tokens WHERE native_generation=2) FROM auth_issuer_native_families f")
        .bind(second.refresh_token().verifier().as_slice()).bind(second.access_token().verifier().as_slice()).fetch_one(&f.base.pool).await.unwrap();
    assert!(exact);
    let actors:bool=sqlx::query_scalar("SELECT count(*)=2 AND bool_and(actor_session_id IS NULL AND session_id IS NULL AND issuer_credential_kind='refresh_token' AND issuer_generation>0) FROM auth_audit WHERE kind='issuer_native_rotated'")
        .fetch_one(&f.base.pool).await.unwrap();
    assert!(actors);
    assert!(
        f.base
            .store
            .authenticate(f.base.authority.realm(), second.access_token().verifier())
            .await
            .is_err()
    );
    assert!(matches!(
        auth_core::IssuerTokenManagement::new(f.base.authority.clone(), f.base.store.clone())
            .introspect_access(
                &f.authentication(),
                &second.access_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidClient)
    ));
}

#[sqlx::test]
async fn reuse_of_spent_refresh_commits_family_and_descendant_access_revocation_permanently(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let initial = f.exchange(&code).await.unwrap();
    let refresh = f.refresher();
    let next = refresh
        .refresh(
            &f.authentication(),
            &initial.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert!(matches!(
        refresh
            .refresh(
                &f.authentication(),
                &initial.refresh_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    let at: i64 = sqlx::query_scalar("SELECT revoked_at_us FROM auth_issuer_native_families")
        .fetch_one(&f.base.pool)
        .await
        .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT bool_and(revoked_at_us IS NOT NULL) FROM auth_issuer_access_tokens"
        )
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
    assert!(matches!(
        refresh
            .refresh(
                &f.authentication(),
                &next.refresh_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert!(matches!(
        refresh
            .refresh(
                &f.authentication(),
                &initial.refresh_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT revoked_at_us FROM auth_issuer_native_families")
            .fetch_one(&f.base.pool)
            .await
            .unwrap(),
        at
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM auth_audit WHERE kind='issuer_native_reuse_revoked'"
        )
        .fetch_one(&f.base.pool)
        .await
        .unwrap(),
        1
    );
}

#[sqlx::test]
async fn rotation_audit_failure_rolls_back_spend_generation_idle_and_new_credentials(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let initial = f.exchange(&code).await.unwrap();
    let before: (i64, i64) =
        sqlx::query_as("SELECT generation,idle_until_us FROM auth_issuer_native_families")
            .fetch_one(&f.base.pool)
            .await
            .unwrap();
    sqlx::raw_sql("ALTER TABLE auth_audit ADD CONSTRAINT owned_rotation_fault CHECK (kind<>'issuer_native_rotated') NOT VALID").execute(&f.base.pool).await.unwrap();
    assert!(matches!(
        f.refresher()
            .refresh(
                &f.authentication(),
                &initial.refresh_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::Unavailable)
    ));
    assert_eq!(
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT generation,idle_until_us FROM auth_issuer_native_families"
        )
        .fetch_one(&f.base.pool)
        .await
        .unwrap(),
        before
    );
    assert_eq!(f.facts().await, (1, 1, 1, 1, 1));
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT spent_at_us IS NULL FROM auth_issuer_native_refresh_tokens"
        )
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
    sqlx::raw_sql("ALTER TABLE auth_audit DROP CONSTRAINT owned_rotation_fault")
        .execute(&f.base.pool)
        .await
        .unwrap();
    let _rotated = f
        .refresher()
        .refresh(
            &f.authentication(),
            &initial.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(f.facts().await, (1, 2, 2, 1, 1));
}

#[sqlx::test]
async fn two_database_only_refreshes_of_one_credential_rotate_once_then_detect_reuse(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let initial = f.exchange(&code).await.unwrap();
    // Concrete initial signing is complete. Only database credential operations
    // run concurrently; no signature/concurrency experiment is performed.
    let refresh = f.refresher();
    let auth = f.authentication();
    let token = initial.refresh_token().into();
    let (a, b) = tokio::join!(
        refresh.refresh(&auth, &token, "127.0.0.1"),
        refresh.refresh(&auth, &token, "127.0.0.1")
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        usize::from(matches!(a, Err(IssuerTokenError::InvalidGrant)))
            + usize::from(matches!(b, Err(IssuerTokenError::InvalidGrant))),
        1
    );
    assert_eq!(f.facts().await, (1, 2, 2, 1, 1));
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT revoked_at_us IS NOT NULL FROM auth_issuer_native_families"
        )
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
}
