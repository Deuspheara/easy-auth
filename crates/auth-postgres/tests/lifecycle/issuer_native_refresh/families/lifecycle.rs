use super::*;
use auth_core::{IssuerTokenError, Repository};

#[sqlx::test]
async fn actual_revoke_all_prevents_refresh_without_touching_or_recreating_the_revoked_session(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let initial = f.exchange(&code).await.unwrap();
    f.base
        .store
        .revoke_all_sessions(f.base.authority.realm(), f.base.current.verifier())
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
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT bool_and(revoked_at IS NOT NULL) FROM auth_sessions WHERE realm_id=$1"
        )
        .bind(f.base.authority.realm())
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
    assert_eq!(f.facts().await, (1, 1, 1, 1, 1));
    f.refresher()
        .revoke(
            &f.authentication(),
            &initial.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT revoked_at_us IS NOT NULL FROM auth_issuer_native_families"
        )
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
}

#[sqlx::test]
async fn credential_revocation_audit_failure_rolls_back_reduction_and_retry_commits_it(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let initial = f.exchange(&code).await.unwrap();
    sqlx::raw_sql("ALTER TABLE auth_audit ADD CONSTRAINT owned_revoke_fault CHECK(kind<>'issuer_native_revoked') NOT VALID")
        .execute(&f.base.pool).await.unwrap();
    assert!(matches!(
        f.refresher()
            .revoke(
                &f.authentication(),
                &initial.refresh_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::Unavailable)
    ));
    assert!(sqlx::query_scalar::<_, bool>("SELECT f.revoked_at_us IS NULL AND a.revoked_at_us IS NULL FROM auth_issuer_native_families f JOIN auth_issuer_access_tokens a ON a.native_family_id=f.id")
        .fetch_one(&f.base.pool).await.unwrap());
    sqlx::raw_sql("ALTER TABLE auth_audit DROP CONSTRAINT owned_revoke_fault")
        .execute(&f.base.pool)
        .await
        .unwrap();
    f.refresher()
        .revoke(
            &f.authentication(),
            &initial.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert!(sqlx::query_scalar::<_, bool>("SELECT f.revoked_at_us IS NOT NULL AND a.revoked_at_us IS NOT NULL FROM auth_issuer_native_families f JOIN auth_issuer_access_tokens a ON a.native_family_id=f.id")
        .fetch_one(&f.base.pool).await.unwrap());
}
