use super::{
    actor::{self, Observer},
    setup::Fixture,
    socket::stopped,
};
use crate::{GoogleDesktopLaunchError, GoogleDesktopSignInError};
use serde_json::json;
use sqlx::PgPool;
use std::{future::pending, process::Command, sync::atomic::Ordering, time::Duration};

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn unavailable_native_command_selection_closes_listener_without_cancelling_sql(pool: PgPool) {
    let mut f = Fixture::stable(pool, "127.0.0.1".parse().unwrap()).await;
    let mut attempt = f.begin().await;
    let revision = f.policy.configuration().revision();
    let expiry = attempt.start.transaction.expires_us;
    assert!(matches!(
        attempt
            .run_prepared(Err(GoogleDesktopLaunchError::Unavailable.into()), pending())
            .await,
        Err(GoogleDesktopSignInError::Launch(
            GoogleDesktopLaunchError::Unavailable
        ))
    ));
    stopped(&f.uri()).await;
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    assert_eq!(attempt.start.transaction.expires_us, expiry);
    let stored_expiry: i64 = sqlx::query_scalar(
        "SELECT (extract(epoch FROM expires_at)*1000000)::bigint FROM auth_oauth_transactions WHERE realm_id=$1 AND state_hash=$2",
    )
    .bind(f.policy.configuration().realm())
    .bind(attempt.start.transaction.state.verifier().as_slice())
    .fetch_one(&f.pool)
    .await
    .expect("test infrastructure: original pending expiry");
    assert_eq!(stored_expiry, expiry);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 0);
    attempt.cancel().await.unwrap();
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));

    f.reopen("127.0.0.1".parse().unwrap()).await;
    assert_eq!(f.policy.configuration().revision(), revision);
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    f.commit(attempt.run_prepared(Ok(command), pending()).await.unwrap())
        .await;
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn missing_native_opener_is_infrastructure_failure_with_explicit_pending_cleanup(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, "127.0.0.1".parse().unwrap()).await;
    let mut attempt = f.begin().await;
    let absent =
        std::env::temp_dir().join(format!("easy-auth-owned-absent-{}", uuid::Uuid::new_v4()));
    assert!(!absent.exists());
    assert!(matches!(
        attempt.run_with(Command::new(absent), pending()).await,
        Err(GoogleDesktopSignInError::Launch(
            GoogleDesktopLaunchError::Unavailable
        ))
    ));
    stopped(&f.uri()).await;
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    attempt.cancel().await.unwrap();
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.rebind().await;
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    f.commit(attempt.run_with(command, pending()).await.unwrap())
        .await;
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn dropped_native_future_closes_owned_resources_without_claiming_sql_cancellation(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, "127.0.0.1".parse().unwrap()).await;
    let mut attempt = f.begin().await;
    let observer = Observer::new().await;
    let command = actor::command(&attempt, None, "wait", Some(&observer));
    let task = tokio::spawn(async move { attempt.run_with(command, pending()).await });
    let stream = observer.started().await;
    task.abort();
    let result = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("test infrastructure: owned task cancellation observed");
    assert!(result.is_err_and(|error| error.is_cancelled()));
    // EOF proves this owned child no longer holds its socket. This is not a
    // claim that the caller received confirmed reaping or asynchronous SQL cleanup.
    Observer::closed(stream).await;
    stopped(&f.uri()).await;
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    f.rebind().await;
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    f.commit(attempt.run_with(command, pending()).await.unwrap())
        .await;
}
