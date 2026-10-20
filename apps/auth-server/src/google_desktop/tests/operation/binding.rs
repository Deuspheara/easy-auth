use super::super::{GoogleDesktopSignIn, launch};
use super::{
    actor,
    setup::{Fixture, SOURCE},
    socket::stopped,
};
use crate::{GoogleDesktopError, GoogleDesktopListener, GoogleDesktopSignInError};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::{future::pending, sync::atomic::Ordering};

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn owned_native_mismatched_listener_and_invalid_source_fail_before_admission_or_launch(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, "127.0.0.1".parse().unwrap()).await;
    let wrong =
        GoogleDesktopListener::bind("127.0.0.1".parse().unwrap(), "/different/owned/return")
            .await
            .unwrap();
    let uri = url::Url::parse(wrong.redirect().as_str()).unwrap();
    assert!(matches!(
        GoogleDesktopSignIn::begin(wrong, f.service.clone(), SOURCE).await,
        Err(GoogleDesktopSignInError::Transport(
            GoogleDesktopError::InvalidInput
        ))
    ));
    stopped(&uri).await;
    let listener = f.listener.take().unwrap();
    assert!(matches!(
        GoogleDesktopSignIn::begin(listener, f.service.clone(), "").await,
        Err(GoogleDesktopSignInError::Core(Error::InvalidInput))
    ));
    stopped(&f.uri()).await;
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(f.provider.document_gets.load(Ordering::SeqCst), 0);
    f.rebind().await;
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    f.commit(attempt.run_with(command, pending()).await.unwrap())
        .await;
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_platform_command_keeps_exact_protocol_url_as_data_without_private_proof(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, "127.0.0.1".parse().unwrap()).await;
    let attempt = f.begin().await;
    let command = launch::command(&attempt.start.authorization_url).unwrap();
    let url = attempt.start.authorization_url.expose();
    assert!(!url.contains(attempt.start.transaction.proof.pkce_verifier().expose()));
    #[cfg(target_os = "macos")]
    {
        assert_eq!(command.get_program(), "/usr/bin/open");
        let arguments: Vec<_> = command.get_args().collect();
        assert!(
            arguments.len() == 2 && arguments[0] == "--" && arguments[1] == url,
            "exact URL is one data argument after end-of-options"
        );
    }
    #[cfg(target_os = "linux")]
    {
        assert!(
            matches!(
                command.get_program().to_str(),
                Some("xdg-open" | "powershell.exe")
            ),
            "only first platform opener selected, without fallback iteration"
        );
        let exact_argument = command.get_args().any(|argument| argument == url);
        let exact_environment = command
            .get_envs()
            .any(|(key, value)| key == "OPEN_RS_TARGET" && value.is_some_and(|value| value == url));
        assert!(
            exact_argument || exact_environment,
            "target is literal data, never interpolated shell source"
        );
    }
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    attempt.cancel().await.unwrap();
    stopped(&f.uri()).await;
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_rebind_preserves_identity_but_intentionally_invalidates_previous_source_session_revision(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, "127.0.0.1".parse().unwrap()).await;
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    let (owner, old_session) = f
        .commit(attempt.run_with(command, pending()).await.unwrap())
        .await;
    f.rebind().await;
    assert!(
        matches!(
            f.store
                .authenticate(owner.realm_id, old_session.verifier())
                .await,
            Err(Error::Unauthorized)
        ),
        "loopback reconfiguration cannot bypass the existing source-revision guard"
    );
    assert_eq!(
        f.facts().await,
        (1, 1, 1, 1, 0),
        "an unrevoked stored row is not current session authority"
    );
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    let (again, current) = f
        .commit(attempt.run_with(command, pending()).await.unwrap())
        .await;
    assert_eq!(
        again.id, owner.id,
        "same scoped Google subject retains its owner"
    );
    assert_eq!(
        f.store
            .authenticate(owner.realm_id, current.verifier())
            .await
            .unwrap(),
        owner
    );
    assert_eq!(f.facts().await, (1, 1, 2, 2, 0));
}
