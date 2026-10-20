use super::setup::Fixture;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn signed_subjects_remain_case_sensitive_under_explicit_database_collation(pool: PgPool) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (upper, _) = f
        .sign_in
        .finish(f.mapped("Subject", json!({})).await)
        .await
        .unwrap();
    let (lower, _) = f
        .sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    assert_ne!(upper.id, lower.id);
    let columns: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_attribute WHERE attrelid='auth_oidc_identities'::regclass AND attname IN ('issuer','subject') AND attcollation='\"C\"'::regcollation").fetch_one(&f.pool).await.unwrap();
    assert_eq!(
        columns, 2,
        "identity equality must not depend on a database's default locale"
    );
    assert_eq!(f.facts().await, (2, 2, 2, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn changing_allowed_exact_issuer_does_not_transfer_same_subject_to_previous_owner(
    pool: PgPool,
) {
    let mut first = Fixture::new(pool.clone(), OidcJitPolicy::Allow).await;
    let (original, old) = first
        .sign_in
        .finish(first.mapped("same-subject", json!({})).await)
        .await
        .unwrap();
    let c = first.policy.configuration();
    let connection = OAuthConnection::new(
        c.realm(),
        c.connection(),
        c.client(),
        "https://tenant.example/other",
        c.provider_client(),
        c.redirect(),
        c.defense(),
    )
    .unwrap();
    let policy = OidcIdentityPolicy::new(
        connection,
        &["https://issuer.example", "https://tenant.example/other"],
        OidcDisplayNameClaim::Name,
    )
    .unwrap()
    .with_jit(OidcJitPolicy::Allow);
    let second = Fixture::configured(pool, first.store.clone(), policy).await;
    let (different, new) = second
        .sign_in
        .finish(second.mapped("same-subject", json!({})).await)
        .await
        .unwrap();
    assert_ne!(different.id, original.id);
    assert!(matches!(
        first
            .store
            .authenticate(first.realm(), old.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    second
        .store
        .authenticate(second.realm(), new.verifier())
        .await
        .unwrap();
    first.reconfigure(OidcJitPolicy::Deny).await;
    let (restored, _) = first
        .sign_in
        .finish(first.mapped("same-subject", json!({})).await)
        .await
        .unwrap();
    assert_eq!(
        restored, original,
        "only a fresh proof for the restored exact issuer resolves its original bound owner"
    );
    assert!(matches!(
        first
            .store
            .authenticate(first.realm(), new.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(first.facts().await, (2, 2, 3, 3, 0));
}
