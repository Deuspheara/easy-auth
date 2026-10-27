use super::fixture::*;
use sqlx::PgPool;
#[sqlx::test(migrations = "./migrations")]
async fn expiry_erases_ciphertext_without_confirming_and_keeps_other_realms_intact(pool: PgPool) {
    let f = Fixture::new(pool.clone(), AppleClientType::Web, OidcJitPolicy::Deny).await;
    pending(&f).await;
    let other = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Deny).await;
    pending(&other).await;
    sqlx::query("UPDATE auth_apple_grants SET queued_at=statement_timestamp()-interval '604801 seconds',expires_at=statement_timestamp()-interval '1 second' WHERE realm_id=$1")
        .bind(f.realm()).execute(&f.pool).await.unwrap();
    assert_eq!(f.store.maintain_apple_grants(f.realm()).await.unwrap(), 1);
    assert_eq!(
        state(&f).await,
        ("expired".into(), 0, Some("expired".into()), true)
    );
    assert!(!state(&other).await.3);
    let http = Http::new(&f);
    assert_eq!(
        worker(&f, http.clone()).run_once().await.unwrap(),
        AppleRevocationOutcome::Idle
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
}
