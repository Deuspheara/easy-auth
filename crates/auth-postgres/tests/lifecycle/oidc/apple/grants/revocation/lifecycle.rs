use super::fixture::*;
use sqlx::PgPool;
#[sqlx::test(migrations = "./migrations")]
async fn fixed_endpoint_actual_client_signature_and_empty_success_confirm_without_local_session_changes(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Deny).await;
    let (owner, current, _) = pending(&f).await;
    let http = Http::new(&f);
    let worker = worker(&f, http.clone());
    let c = f.policy.configuration();
    f.store
        .disable_oauth_connection(c.realm(), c.connection(), c.client())
        .await
        .unwrap();
    assert_eq!(
        worker.run_once().await.unwrap(),
        AppleRevocationOutcome::Confirmed
    );
    assert_eq!(state(&f).await, ("completed".into(), 1, None, true));
    assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.store
            .authenticate(f.realm(), current.verifier())
            .await
            .unwrap(),
        owner
    );
    assert_eq!(
        worker.run_once().await.unwrap(),
        AppleRevocationOutcome::Idle
    );
}
#[sqlx::test(migrations = "./migrations")]
async fn provider_and_transport_errors_keep_ciphertext_and_cannot_busy_retry_or_claim_success(
    pool: PgPool,
) {
    for (mode, failure) in [
        (Mode::Transport, AppleRevocationFailure::Transport),
        (Mode::InvalidClient, AppleRevocationFailure::Configuration),
        (Mode::InvalidGrant, AppleRevocationFailure::Provider),
        (Mode::FalseSuccess, AppleRevocationFailure::Provider),
        (Mode::Compressed, AppleRevocationFailure::Provider),
    ] {
        let f = Fixture::new(pool.clone(), AppleClientType::Web, OidcJitPolicy::Deny).await;
        let (_, _, _) = pending(&f).await;
        let http = Http::new(&f);
        *http.mode.lock().unwrap() = mode;
        let worker = worker(&f, http.clone());
        assert_eq!(
            worker.run_once().await.unwrap(),
            AppleRevocationOutcome::Deferred(failure)
        );
        let row = state(&f).await;
        assert_eq!(row.0, "pending");
        assert_eq!(row.1, 1);
        assert!(!row.3);
        assert_eq!(
            worker.run_once().await.unwrap(),
            AppleRevocationOutcome::Idle
        );
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    }
}
