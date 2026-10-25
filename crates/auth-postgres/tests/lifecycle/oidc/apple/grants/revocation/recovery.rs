use super::fixture::*;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn crashed_claim_is_recovered_after_real_lease_without_accepting_old_generation(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Deny).await;
    let (owner, current, id) = pending(&f).await;
    let source = f.policy.configuration();
    let old = f
        .store
        .claim_apple_revocation(source)
        .await
        .unwrap()
        .unwrap();
    let http = Http::new(&f);
    let worker = worker(&f, http.clone());
    assert_eq!(
        worker.run_once().await.unwrap(),
        AppleRevocationOutcome::Idle
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    assert!(!f.store.rotate_apple_grant_key(f.realm(), id).await.unwrap());
    assert_eq!(state(&f).await, ("leased".into(), 1, None, false));
    // No artificial clock, shortened lease, or direct lifecycle mutation. A
    // process dying after its committed claim is represented by no ACK/defer.
    wait_clock(&f.pool, old.until_us()).await;
    assert_eq!(
        worker.run_once().await.unwrap(),
        AppleRevocationOutcome::Confirmed
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    assert_eq!(state(&f).await, ("completed".into(), 2, None, true));
    assert!(
        !f.store
            .defer_apple_revocation(source, &old, AppleRevocationFailure::Provider)
            .await
            .unwrap()
    );
    assert!(matches!(
        f.store.check_apple_revocation(source, &old).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.store
            .authenticate(f.realm(), current.verifier())
            .await
            .unwrap(),
        owner
    );
}
