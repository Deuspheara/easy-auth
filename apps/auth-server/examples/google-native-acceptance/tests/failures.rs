use super::{fixture::Fixture, provider::Provider};
use crate::{completion, observations, settings::ClaimsProfile};
use auth_core::{Error, GoogleAuthorizationCompletion, Secret};
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn manual_completion_distinguishes_signed_rejection_from_provider_transport_failure(
    pool: PgPool,
) {
    for unavailable in [false, true] {
        let provider = Provider::new();
        provider.unavailable.store(unavailable, Ordering::SeqCst);
        let attributes = if unavailable {
            json!({})
        } else {
            json!({"nonce":Secret::generate().unwrap().expose()})
        };
        let delivered = Fixture::new(
            pool.clone(),
            ClaimsProfile::Base,
            "127.0.0.1".parse().unwrap(),
            provider.clone(),
        )
        .await
        .delivered(attributes)
        .await;
        assert!(matches!(
            (&delivered.result, unavailable),
            (Err(Error::Unavailable), true) | (Err(Error::Unauthorized), false)
        ));
        assert_eq!(provider.posts.load(Ordering::SeqCst), 1);
        assert_eq!(
            provider.signed.load(Ordering::SeqCst),
            usize::from(!unavailable)
        );
        assert_eq!(
            observations::read(&pool, delivered.policy.configuration().realm())
                .await
                .unwrap(),
            (0, 0, 0, 0, 0, 0)
        );
        provider.unavailable.store(false, Ordering::SeqCst);
        let good = Fixture::new(
            pool.clone(),
            ClaimsProfile::Base,
            "127.0.0.1".parse().unwrap(),
            provider.clone(),
        )
        .await
        .delivered(json!({}))
        .await;
        completion::commit(&pool, &good.store, &good.policy, good.result.unwrap())
            .await
            .unwrap();
        assert_eq!(
            provider.signed.load(Ordering::SeqCst),
            usize::from(!unavailable) + 1
        );
    }
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn required_session_age_claim_remains_a_signed_profile_failure(pool: PgPool) {
    let missing = Fixture::new(
        pool.clone(),
        ClaimsProfile::SessionAge,
        "127.0.0.1".parse().unwrap(),
        Provider::new(),
    )
    .await
    .delivered(json!({}))
    .await;
    assert!(
        matches!(missing.result, Err(Error::Unavailable)),
        "signed missing claim is a profile failure"
    );
    assert_eq!(missing.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(
        observations::read(&pool, missing.policy.configuration().realm())
            .await
            .unwrap(),
        (0, 0, 0, 0, 0, 0)
    );
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn denied_or_failed_provider_completion_cannot_issue_local_authority(pool: PgPool) {
    for denied in [true, false] {
        let fixture = Fixture::new(
            pool.clone(),
            ClaimsProfile::Base,
            "127.0.0.1".parse().unwrap(),
            Provider::new(),
        )
        .await;
        let value = if denied {
            GoogleAuthorizationCompletion::Denied
        } else {
            GoogleAuthorizationCompletion::ProviderFailure
        };
        assert_eq!(
            completion::commit(&pool, &fixture.setup.store, &fixture.setup.policy, value)
                .await
                .err(),
            Some(if denied {
                "provider_denied"
            } else {
                "provider_failure"
            })
        );
        assert_eq!(
            observations::read(&pool, fixture.setup.policy.configuration().realm())
                .await
                .unwrap(),
            (0, 0, 0, 0, 0, 0)
        );
    }
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn actual_source_disable_rejects_preverified_manual_completion(pool: PgPool) {
    let current = Fixture::new(
        pool.clone(),
        ClaimsProfile::Base,
        "127.0.0.1".parse().unwrap(),
        Provider::new(),
    )
    .await
    .delivered(json!({}))
    .await;
    let configuration = current.policy.configuration();
    current
        .store
        .disable_oauth_connection(
            configuration.realm(),
            configuration.connection(),
            configuration.client(),
        )
        .await
        .unwrap();
    assert_eq!(
        completion::commit(
            &pool,
            &current.store,
            &current.policy,
            current.result.unwrap()
        )
        .await
        .err(),
        Some("local_authority_rejected")
    );
    assert_eq!(
        observations::read(&pool, configuration.realm())
            .await
            .unwrap(),
        (0, 0, 0, 0, 0, 0)
    );
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn actual_audit_storage_failure_rolls_back_the_manual_commit_without_becoming_a_denial(
    pool: PgPool,
) {
    let provider = Provider::new();
    let valid = Fixture::new(
        pool.clone(),
        ClaimsProfile::Base,
        "127.0.0.1".parse().unwrap(),
        provider.clone(),
    )
    .await
    .delivered(json!({}))
    .await;
    let realm = valid.policy.configuration().realm();
    sqlx::query("ALTER TABLE auth_audit RENAME TO owned_unavailable_audit")
        .execute(&pool)
        .await
        .expect("test infrastructure: arrange owned audit fault");
    let result =
        completion::commit(&pool, &valid.store, &valid.policy, valid.result.unwrap()).await;
    sqlx::query("ALTER TABLE owned_unavailable_audit RENAME TO auth_audit")
        .execute(&pool)
        .await
        .expect("test infrastructure: restore owned audit");
    assert_eq!(result.err(), Some("local_storage_unavailable"));
    assert_eq!(provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(
        observations::read(&pool, realm).await.unwrap(),
        (0, 0, 0, 0, 0, 0)
    );
    let retry = Fixture::new(
        pool.clone(),
        ClaimsProfile::Base,
        "127.0.0.1".parse().unwrap(),
        provider.clone(),
    )
    .await
    .delivered(json!({}))
    .await;
    completion::commit(&pool, &retry.store, &retry.policy, retry.result.unwrap())
        .await
        .unwrap();
    assert_eq!(provider.signed.load(Ordering::SeqCst), 2);
}
