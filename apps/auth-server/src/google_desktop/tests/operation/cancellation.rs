use super::{
    actor::{self, Observer},
    setup::Fixture,
    socket::stopped,
};
use crate::{GoogleDesktopError, GoogleDesktopLaunchError, GoogleDesktopSignInError};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::{
    future::{pending, ready},
    process::Command,
    sync::atomic::Ordering,
    time::Duration,
};
use tokio::sync::oneshot;

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn already_cancelled_native_attempt_does_not_invoke_even_a_missing_opener(pool: PgPool) {
    let mut f = Fixture::new(pool, "127.0.0.1".parse().unwrap()).await;
    let mut attempt = f.begin().await;
    let absent =
        std::env::temp_dir().join(format!("easy-auth-owned-absent-{}", uuid::Uuid::new_v4()));
    assert!(!absent.exists());
    assert!(matches!(
        attempt.run_with(Command::new(absent), ready(())).await,
        Err(GoogleDesktopSignInError::Transport(
            GoogleDesktopError::Cancelled
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
async fn successful_opener_exit_without_owned_callback_never_completes_authentication(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, "127.0.0.1".parse().unwrap()).await;
    let mut attempt = f.begin().await;
    let observer = Observer::new().await;
    let command = actor::command(&attempt, None, "exit", Some(&observer));
    let (cancel, cancelled) = oneshot::channel();
    let task = tokio::spawn(async move {
        let result = attempt
            .run_with(command, async {
                let _ = cancelled.await;
            })
            .await;
        (attempt, result)
    });
    let stream = observer.started().await;
    Observer::closed(stream).await;
    assert!(
        !task.is_finished(),
        "opener exit0 without callback cannot return proof"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    cancel.send(()).unwrap();
    let (attempt, result) = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(GoogleDesktopSignInError::Transport(
            GoogleDesktopError::Cancelled
        ))
    ));
    stopped(&f.uri()).await;
    attempt.cancel().await.unwrap();
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_cancellation_kills_and_reaps_only_its_actual_running_opener(pool: PgPool) {
    let mut f = Fixture::new(pool, "127.0.0.1".parse().unwrap()).await;
    let mut attempt = f.begin().await;
    let observer = Observer::new().await;
    let command = actor::command(&attempt, None, "wait", Some(&observer));
    let (cancel, cancelled) = oneshot::channel();
    let action = async {
        let stream = observer.started().await;
        cancel.send(()).unwrap();
        stream
    };
    let (result, stream) = tokio::join!(
        attempt.run_with(command, async {
            let _ = cancelled.await;
        }),
        action
    );
    assert!(matches!(
        result,
        Err(GoogleDesktopSignInError::Transport(
            GoogleDesktopError::Cancelled
        ))
    ));
    Observer::closed(stream).await;
    stopped(&f.uri()).await;
    assert_eq!(
        f.facts().await,
        (0, 0, 0, 0, 1),
        "transport cancellation is not database cancellation"
    );
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
async fn native_opener_and_original_operation_deadlines_are_distinct_and_never_extend_authority(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, "127.0.0.1".parse().unwrap()).await;
    for short_cap in [false, true] {
        let mut attempt = f.begin().await;
        if short_cap {
            f.cap(&mut attempt, 3).await;
        }
        let observer = Observer::new().await;
        let command = actor::command(&attempt, None, "wait", Some(&observer));
        let (result, stream) =
            tokio::join!(attempt.run_with(command, pending()), observer.started());
        assert!(matches!(
            (short_cap, result),
            (
                false,
                Err(GoogleDesktopSignInError::Launch(
                    GoogleDesktopLaunchError::TimedOut
                ))
            ) | (
                true,
                Err(GoogleDesktopSignInError::Transport(
                    GoogleDesktopError::Expired
                ))
            )
        ));
        Observer::closed(stream).await;
        stopped(&f.uri()).await;
        assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
        assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
        if short_cap {
            let expired: bool =
                sqlx::query_scalar("SELECT clock_timestamp()>=to_timestamp($1::numeric/1000000)")
                    .bind(attempt.start.transaction.expires_us)
                    .fetch_one(&f.pool)
                    .await
                    .expect("test infrastructure: original database deadline crossed");
            assert!(
                expired,
                "the actual original database deadline must be crossed"
            );
            assert!(matches!(attempt.cancel().await, Err(Error::Unauthorized)));
        } else {
            attempt.cancel().await.unwrap();
        }
        f.rebind().await;
    }
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    f.commit(attempt.run_with(command, pending()).await.unwrap())
        .await;
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn cancellation_during_native_token_io_never_returns_proof_or_restores_consumed_state(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, "127.0.0.1".parse().unwrap()).await;
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    f.provider.hold.store(true, Ordering::SeqCst);
    let (cancel, cancelled) = oneshot::channel();
    let action = async {
        tokio::time::timeout(Duration::from_secs(3), f.provider.entered.notified())
            .await
            .expect("test infrastructure: actual native token POST held");
        cancel.send(()).unwrap();
    };
    let (result, ()) = tokio::join!(
        attempt.run_with(command, async {
            let _ = cancelled.await;
        }),
        action
    );
    assert!(matches!(
        result,
        Err(GoogleDesktopSignInError::Transport(
            GoogleDesktopError::Cancelled
        ))
    ));
    f.provider.hold.store(false, Ordering::SeqCst);
    f.provider.release.notify_one();
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 0);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert!(matches!(attempt.cancel().await, Err(Error::Unauthorized)));
    f.rebind().await;
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    f.commit(attempt.run_with(command, pending()).await.unwrap())
        .await;
}
