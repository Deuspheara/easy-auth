use super::fixture::*;
use josekit::jwk::KeyPair;
use sqlx::PgPool;
#[sqlx::test(migrations = "./migrations")]
async fn missing_storage_key_or_mismatched_encrypted_client_never_sends_a_credential(pool: PgPool) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Deny).await;
    pending(&f).await;
    let http = Http::new(&f);
    let w = AppleGrantRevoker::new(
        f.policy.configuration().clone(),
        f.store.clone(),
        f.signer.clone(),
        new_vault(),
        f.store.clone(),
        f.provider.clone(),
        http.clone(),
    )
    .unwrap();
    assert_eq!(
        w.run_once().await.unwrap(),
        AppleRevocationOutcome::Deferred(AppleRevocationFailure::Configuration)
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    // Owned corruption/reconfiguration fixture: ciphertext still authenticates
    // the original provider client even when clear dispatch metadata is changed.
    let c = f.policy.configuration();
    let changed = OAuthConnection::new(
        c.realm(),
        c.connection(),
        c.client(),
        c.issuer(),
        "com.example.other",
        c.redirect(),
        c.defense(),
    )
    .unwrap();
    sqlx::query("UPDATE auth_apple_grants SET provider_client=$2,next_attempt_at=clock_timestamp() WHERE realm_id=$1")
        .bind(f.realm()).bind(changed.provider_client()).execute(&f.pool).await.unwrap();
    let key = josekit::jws::ES256.generate_key_pair().unwrap();
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let signer = Arc::new(
        AppleClientSecretSigner::from_pkcs8_pem(
            "TEAM000001",
            changed.provider_client(),
            "KEY0000001",
            (now - 1) as u64,
            (now + 3600) as u64,
            String::from_utf8(key.to_pem_private_key()).unwrap(),
        )
        .unwrap(),
    );
    let w = AppleGrantRevoker::new(
        changed,
        f.store.clone(),
        signer,
        f.vault.clone(),
        f.store.clone(),
        f.provider.clone(),
        http.clone(),
    )
    .unwrap();
    assert_eq!(
        w.run_once().await.unwrap(),
        AppleRevocationOutcome::Deferred(AppleRevocationFailure::Configuration)
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    assert!(!state(&f).await.3);
}
#[sqlx::test(migrations = "./migrations")]
async fn exhausted_attempts_are_visible_failures_then_expire_without_becoming_success(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Deny).await;
    pending(&f).await;
    sqlx::query("UPDATE auth_apple_grants SET attempts=7 WHERE realm_id=$1")
        .bind(f.realm())
        .execute(&f.pool)
        .await
        .unwrap();
    let http = Http::new(&f);
    *http.mode.lock().unwrap() = Mode::InvalidClient;
    let w = worker(&f, http.clone());
    assert_eq!(
        w.run_once().await.unwrap(),
        AppleRevocationOutcome::Deferred(AppleRevocationFailure::Configuration)
    );
    assert_eq!(
        state(&f).await,
        ("failed".into(), 8, Some("configuration".into()), false)
    );
    assert_eq!(w.run_once().await.unwrap(), AppleRevocationOutcome::Idle);
    assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    sqlx::query("UPDATE auth_apple_grants SET queued_at=statement_timestamp()-interval '604801 seconds',expires_at=statement_timestamp()-interval '1 second' WHERE realm_id=$1")
        .bind(f.realm()).execute(&f.pool).await.unwrap();
    f.store.maintain_apple_grants(f.realm()).await.unwrap();
    assert_eq!(state(&f).await.0, "expired");
    assert!(state(&f).await.3);
    sqlx::query("UPDATE auth_apple_grants SET finished_at=statement_timestamp()-interval '604801 seconds' WHERE realm_id=$1")
        .bind(f.realm()).execute(&f.pool).await.unwrap();
    f.store.maintain_apple_grants(f.realm()).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_apple_grants WHERE realm_id=$1")
        .bind(f.realm())
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
