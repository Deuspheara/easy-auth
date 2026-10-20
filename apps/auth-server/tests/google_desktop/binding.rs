use super::{delivery, setup::Fixture};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::Ordering,
};

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_callback_from_another_owned_listener_cannot_substitute_the_original_return_uri(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool.clone(), IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let mut foreign = Fixture::new(pool, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let a = f.begin(json!({}), None).await;
    // Deliberately deliver valid state/code to a different real owned socket.
    // Native delivery alone must not let that socket stand in for the configured URI.
    let captured = delivery::capture(&mut foreign, &a, None).await;
    assert!(matches!(
        delivery::finish(&f, &a, captured).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    assert_eq!(foreign.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    let captured = delivery::capture(&mut f, &a, None).await;
    f.commit(delivery::finish(&f, &a, captured).await.unwrap())
        .await;
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_rebinding_cancels_old_pending_authority_and_rejects_previously_captured_return(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let a = f.begin(json!({}), None).await;
    let old_service = f.service.clone();
    let old_revision = f.policy.configuration().revision();
    let captured = delivery::capture(&mut f, &a, None).await;
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    f.rebind().await;
    assert_ne!(f.policy.configuration().revision(), old_revision);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert!(matches!(
        captured
            .finish(&old_service, &a.intent(), a.state(), a.proof())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    let a = f.begin(json!({}), None).await;
    let captured = delivery::capture(&mut f, &a, None).await;
    f.commit(delivery::finish(&f, &a, captured).await.unwrap())
        .await;
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_captured_return_racing_a_restored_private_operation_has_one_exchange_and_commit(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let a = f.begin(json!({}), None).await;
    let captured = delivery::capture(&mut f, &a, None).await;
    let intent = a.intent();
    let (actual, replayed) = tokio::join!(
        delivery::finish(&f, &a, captured),
        f.service.finish(
            &intent,
            a.state(),
            a.proof(),
            f.policy.configuration().redirect(),
            a.replay_response()
        )
    );
    let completion = match (actual, replayed) {
        (Ok(completion), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(completion)) => {
            completion
        }
        _ => panic!("one signed callback and one actual replay denial required"),
    };
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.commit(completion).await;
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}
