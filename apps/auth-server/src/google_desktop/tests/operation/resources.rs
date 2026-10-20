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
