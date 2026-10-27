use super::keeping;
use crate::support::issuer_native_families::Fixture;
use auth_core::{
    IssuerNativeRefreshPolicy, IssuerTokenError, RetentionCategory, RetentionHorizon,
    RetentionPolicy, RetentionRepository,
};
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn real_elapsed_native_graph_prunes_leaves_after_audit_and_preserves_durable_configuration(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool).await;
    let realm = f.base.authority.realm();
    // Owned near-expiry session fixture. The ordinary native consent/issuance
    // captures this actual source cap; no grant/history expiry is rewritten later.
    sqlx::query("UPDATE auth_sessions SET expires_at=statement_timestamp()+interval '8 seconds' WHERE realm_id=$1")
        .bind(realm).execute(&f.base.pool).await.unwrap();
    f.policy = f
        .base
        .store
        .configure_issuer_native_refresh_policy(
            &IssuerNativeRefreshPolicy::new(
                f.base.authority.clone(),
                f.policy.client().clone(),
                5,
                5,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    f.base
        .store
        .enable_issuer_native_refresh_policy(&f.policy)
        .await
        .unwrap();
    let code = f.code().await;
    let issued = f.exchange(&code).await.unwrap();
    for category in [
        RetentionCategory::IssuerAccessTokens,
        RetentionCategory::IssuerRefreshTokens,
        RetentionCategory::IssuerFamilies,
        RetentionCategory::IssuerConsents,
        RetentionCategory::IssuerAuthorizations,
        RetentionCategory::Sessions,
    ] {
        assert_eq!(
            f.base
                .store
                .retain_batch(realm, category, keeping())
                .await
                .unwrap()
                .deleted,
            0
        );
    }
    let (cap, now): (i64,i64) = sqlx::query_as("SELECT (extract(epoch FROM expires_at)*1000000)::bigint,(extract(epoch FROM clock_timestamp())*1000000)::bigint FROM auth_sessions WHERE realm_id=$1")
        .bind(realm).fetch_one(&f.base.pool).await.unwrap();
    assert!(
        now < cap,
        "must observe the original source cap before expiry"
    );
    tokio::time::sleep(Duration::from_micros((cap - now) as u64 + 50_000)).await;
    assert_eq!(
        f.base
            .store
            .retain_batch(realm, RetentionCategory::IssuerAccessTokens, keeping())
            .await
            .unwrap()
            .deleted,
        1
    );
    for category in [
        RetentionCategory::IssuerRefreshTokens,
        RetentionCategory::IssuerFamilies,
        RetentionCategory::IssuerConsents,
        RetentionCategory::IssuerAuthorizations,
        RetentionCategory::Sessions,
    ] {
        assert_eq!(
            f.base
                .store
                .retain_batch(realm, category, keeping())
                .await
                .unwrap()
                .deleted,
            0,
            "retained audit/children must pin the expired graph"
        );
    }
    let policy = RetentionPolicy::new(
        RetentionHorizon::after(Duration::from_secs(1)).unwrap(),
        RetentionHorizon::keep(),
    );
    assert!(
        f.base
            .store
            .retain_batch(realm, RetentionCategory::Audit, policy)
            .await
            .unwrap()
            .deleted
            > 0
    );
    for category in [
        RetentionCategory::IssuerRefreshTokens,
        RetentionCategory::IssuerFamilies,
        RetentionCategory::IssuerConsents,
        RetentionCategory::IssuerAuthorizations,
        RetentionCategory::Sessions,
    ] {
        assert_eq!(
            f.base
                .store
                .retain_batch(realm, category, policy)
                .await
                .unwrap()
                .deleted,
            1
        );
        assert_eq!(
            f.base
                .store
                .retain_batch(realm, category, policy)
                .await
                .unwrap()
                .deleted,
            0
        );
    }
    assert!(matches!(
        f.refresher()
            .refresh(
                &f.authentication(),
                &issued.refresh_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    let durable: (i64,i64,i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_clients WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_subjects WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_keys WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_key_sets WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_native_refresh_policies WHERE realm_id=$1)")
        .bind(realm).fetch_one(&f.base.pool).await.unwrap();
    assert_eq!(durable, (1, 2, 1, 1, 1, 1));
}
