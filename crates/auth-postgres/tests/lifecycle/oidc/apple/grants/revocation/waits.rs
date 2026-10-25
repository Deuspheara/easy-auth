use super::fixture::*;
use crate::support::observation as waits;
use sqlx::PgPool;
#[sqlx::test(migrations = "./migrations")]
async fn successful_reply_waiting_on_unchanged_job_cannot_commit_after_original_lease_cap(
    pool: PgPool,
) {
    let f = Arc::new(Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Deny).await);
    pending(&f).await;
    // Retain the complete original7-day eligibility interval while arranging
    // an owned near-expiry job; production lease/retention policies stay unchanged.
    let cap:i64=sqlx::query_scalar("UPDATE auth_apple_grants SET queued_at=statement_timestamp()-interval '604797 seconds',expires_at=statement_timestamp()+interval '3 seconds' WHERE realm_id=$1 RETURNING (extract(epoch FROM expires_at)*1000000)::bigint")
        .bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    let http = Http::new(&f);
    *http.mode.lock().unwrap() = Mode::Hold;
    let w = worker(&f, http.clone());
    let action = tokio::spawn(async move { w.run_once().await });
    tokio::time::timeout(std::time::Duration::from_secs(5), http.entered.notified())
        .await
        .unwrap();
    let observer = waits::observer(&f.pool).await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_apple_grants WHERE realm_id=$1 FOR UPDATE")
        .bind(f.realm())
        .fetch_all(&mut *gate)
        .await
        .unwrap();
    http.release.notify_one();
    waits::locked(&observer, "%SELECT 1 FROM auth_apple_grants%FOR UPDATE%").await;
    let live: bool =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint<$1")
            .bind(cap)
            .fetch_one(&observer)
            .await
            .unwrap();
    assert!(live);
    assert!(!action.is_finished());
    assert!(!state(&f).await.3);
    waits::expired(&observer, cap).await;
    gate.commit().await.unwrap();
    assert_eq!(
        action.await.unwrap().unwrap(),
        AppleRevocationOutcome::Stale
    );
    assert_eq!(http.applied.load(Ordering::SeqCst), 1);
    assert!(!state(&f).await.3);
    f.store.maintain_apple_grants(f.realm()).await.unwrap();
    assert_eq!(state(&f).await.0, "expired");
    observer.close().await;
}
