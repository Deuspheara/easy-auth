use super::*;
use auth_core::{IssuerTokenError, MAX_ISSUER_NATIVE_FAMILIES_PER_OWNER_CLIENT};

#[sqlx::test]
async fn active_family_policy_limit_requires_reduction_before_another_explicit_grant(pool: PgPool) {
    let f = Fixture::new(pool).await;
    // Ordinary sequential issuances test the finite policy boundary; no load,
    // custom producer, concurrent signing or signature timing experiment.
    let mut first = None;
    for _ in 0..MAX_ISSUER_NATIVE_FAMILIES_PER_OWNER_CLIENT {
        let code = f.code().await;
        let issued = f.exchange(&code).await.unwrap();
        first.get_or_insert(issued);
    }
    let code = f.code().await;
    assert!(matches!(
        f.exchange(&code).await,
        Err(IssuerTokenError::RateLimited)
    ));
    assert_eq!(f.facts().await, (10, 10, 10, 10, 10));
    let issued = first.unwrap();
    f.refresher()
        .revoke(
            &f.authentication(),
            &issued.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    let _next = f.exchange(&code).await.unwrap();
    assert_eq!(f.facts().await, (11, 11, 11, 11, 11));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM auth_issuer_native_families WHERE revoked_at_us IS NULL"
        )
        .fetch_one(&f.base.pool)
        .await
        .unwrap(),
        MAX_ISSUER_NATIVE_FAMILIES_PER_OWNER_CLIENT
    );
}
