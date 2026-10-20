use super::setup::Fixture;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn google_same_provider_subject_is_isolated_by_realm_client_and_callback_source(
    pool: PgPool,
) {
    let first = Fixture::new(pool.clone(), false, OidcJitPolicy::Allow).await;
    let second = Fixture::scoped(
        pool.clone(),
        first.store.clone(),
        Uuid::new_v4(),
        first.provider.clone(),
        false,
        OidcJitPolicy::Allow,
    )
    .await;
    let third = Fixture::scoped(
        pool,
        first.store.clone(),
        first.realm(),
        first.provider.clone(),
        true,
        OidcJitPolicy::Allow,
    )
    .await;
    let a = first.prepare("identical-subject", json!({}), None).await;
    let exchange = first.consume(&a).await.unwrap();
    assert!(matches!(
        second
            .google
            .exchange(exchange, a.authorization_code())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(first.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(first.facts().await, (0, 0, 0, 0, 0));
    let cancelled = third.prepare("identical-subject", json!({}), None).await;
    third
        .flow()
        .cancel(
            &cancelled.intent(),
            &cancelled.start.state,
            &cancelled.start.proof,
        )
        .await
        .unwrap();
    assert!(matches!(
        third.verified(&cancelled).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(first.provider.posts.load(Ordering::SeqCst), 0);
    let mut owners = Vec::new();
    for f in [&first, &second, &third] {
        let (user, session) = f
            .sign_in(
                f.mapped(
                    "identical-subject",
                    json!({"email":"same@example.test","email_verified":true}),
                )
                .await,
            )
            .await
            .unwrap();
        assert!(owners.iter().all(|id| *id != user.id));
        owners.push(user.id);
        assert_eq!(
            f.store
                .authenticate(f.realm(), session.verifier())
                .await
                .unwrap(),
            user
        );
        let other = if f.realm() == second.realm() {
            first.realm()
        } else {
            second.realm()
        };
        assert!(matches!(
            f.store.authenticate(other, session.verifier()).await,
            Err(Error::Unauthorized)
        ));
    }
    assert_eq!(first.provider.signed.load(Ordering::SeqCst), 3);
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_google_callback_claims_have_one_token_exchange_and_local_commit(pool: PgPool) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let a = f.prepare("subject", json!({}), None).await;
    let (one, two) = tokio::join!(f.verified(&a), f.verified(&a));
    let identity = match (one, two) {
        (Ok(identity), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(identity)) => {
            identity
        }
        _ => panic!(
            "one verified winner required; infrastructure errors cannot prove one-use rejection"
        ),
    };
    f.sign_in(f.policy.map(identity).unwrap()).await.unwrap();
    assert!(matches!(f.verified(&a).await, Err(Error::Unauthorized)));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn signed_google_nonce_rejection_is_not_a_provider_or_database_failure(pool: PgPool) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let wrong = f
        .prepare(
            "subject",
            json!({"nonce":Secret::generate().unwrap().expose()}),
            None,
        )
        .await;
    assert!(matches!(f.verified(&wrong).await, Err(Error::Unauthorized)));
    assert_eq!(
        f.provider.signed.load(Ordering::SeqCst),
        1,
        "a real signed response preceded the claim denial"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    let unavailable = f.prepare("subject", json!({}), None).await;
    f.provider.unavailable.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.verified(&unavailable).await,
        Err(Error::Unavailable)
    ));
    f.provider.unavailable.store(false, Ordering::SeqCst);
    assert!(matches!(
        f.verified(&unavailable).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.sign_in(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}
