use super::{actor, setup::Fixture, socket::stopped};
use crate::{GoogleDesktopError, GoogleDesktopLaunchError, GoogleDesktopSignInError};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::{future::pending, sync::atomic::Ordering};

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn owned_native_process_can_return_before_exit_but_only_signed_completion_can_commit(
    pool: PgPool,
) {
    for ip in ["127.0.0.1", "::1"] {
        let mut f = Fixture::new(pool.clone(), ip.parse().unwrap()).await;
        let mut attempt = f.begin().await;
        let code = f.issue(&attempt, json!({})).await;
        assert_eq!(format!("{attempt:?}"), "GoogleDesktopSignIn([REDACTED])");
        let command = actor::command(&attempt, Some(&code), "callback", None);
        let result = attempt.run_with(command, pending()).await.unwrap();
        assert_eq!(
            f.facts().await,
            (0, 0, 0, 0, 0),
            "verification/launcher exit confer no local authority"
        );
        assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
        assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
        stopped(&f.uri()).await;
        let again = actor::command(&attempt, None, "fail", None);
        assert!(matches!(
            attempt.run_with(again, pending()).await,
            Err(GoogleDesktopSignInError::Transport(
                GoogleDesktopError::InvalidInput
            ))
        ));
        f.commit(result).await;
        assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
        assert!(
            matches!(attempt.cancel().await, Err(Error::Unauthorized)),
            "consumed operation cannot be cancelled or restored"
        );
        assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    }
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn owned_native_nonzero_launch_never_verifies_even_after_actual_callback_delivery(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, "127.0.0.1".parse().unwrap()).await;
    for mode in ["fail", "callback_then_fail"] {
        let mut attempt = f.begin().await;
        let code = f.issue(&attempt, json!({})).await;
        let command = actor::command(&attempt, Some(&code), mode, None);
        assert!(matches!(
            attempt.run_with(command, pending()).await,
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
    }
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    f.commit(attempt.run_with(command, pending()).await.unwrap())
        .await;
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn owned_native_provider_denial_failure_and_actual_signed_rejection_remain_distinct(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, "127.0.0.1".parse().unwrap()).await;
    for mode in ["access_denied", "server_error"] {
        let mut attempt = f.begin().await;
        let command = actor::command(&attempt, None, mode, None);
        let completed = attempt.run_with(command, pending()).await.unwrap();
        assert!(matches!(
            (mode, completed),
            ("access_denied", GoogleAuthorizationCompletion::Denied)
                | (
                    "server_error",
                    GoogleAuthorizationCompletion::ProviderFailure
                )
        ));
        assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
        assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
        f.rebind().await;
    }
    let mut attempt = f.begin().await;
    let code = f
        .issue(
            &attempt,
            json!({"nonce":Secret::generate().unwrap().expose()}),
        )
        .await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    assert!(matches!(
        attempt.run_with(command, pending()).await,
        Err(GoogleDesktopSignInError::Core(Error::Unauthorized))
    ));
    assert_eq!(
        f.provider.signed.load(Ordering::SeqCst),
        1,
        "actual signed rejection control"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.rebind().await;
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    f.provider.unavailable.store(true, Ordering::SeqCst);
    let command = actor::command(&attempt, Some(&code), "callback", None);
    assert!(matches!(
        attempt.run_with(command, pending()).await,
        Err(GoogleDesktopSignInError::Core(Error::Unavailable))
    ));
    f.provider.unavailable.store(false, Ordering::SeqCst);
    assert_eq!(
        f.provider.signed.load(Ordering::SeqCst),
        1,
        "transport failure is not a signed denial"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.rebind().await;
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    f.commit(attempt.run_with(command, pending()).await.unwrap())
        .await;
}
