use super::{
    actor,
    setup::{Fixture, SOURCE},
    socket::stopped,
};
use crate::GoogleDesktopListener;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::{future::pending, sync::atomic::Ordering};

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_ephemeral_ports_and_ip_families_preserve_source_sessions_across_reopen(
    pool: PgPool,
) {
    let mut f = Fixture::stable(pool, "127.0.0.1".parse().unwrap()).await;
    let original = f.policy.clone();
    let mut attempt = f.begin().await;
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    let (owner, old) = f
        .commit(attempt.run_with(command, pending()).await.unwrap())
        .await;
    for ip in ["::1", "127.0.0.1"] {
        f.policy = f
            .store
            .load_or_initialize_oidc_identity_policy(&original)
            .await
            .unwrap();
        assert_eq!(
            f.policy, original,
            "startup loading preserves the complete source revision"
        );
        f.reopen(ip.parse().unwrap()).await;
        assert_eq!(
            f.store
                .authenticate(owner.realm_id, old.verifier())
                .await
                .unwrap(),
            owner
        );
        let mut attempt = f.begin().await;
        let code = f.issue(&attempt, json!({})).await;
        let command = actor::command(&attempt, Some(&code), "callback", None);
        let (same, _) = f
            .commit(attempt.run_with(command, pending()).await.unwrap())
            .await;
        assert_eq!(same, owner);
        stopped(&f.uri()).await;
        assert_eq!(
            f.store
                .authenticate(owner.realm_id, old.verifier())
                .await
                .unwrap(),
            owner
        );
    }
    assert_eq!(f.facts().await, (1, 1, 3, 3, 0));
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn concurrent_native_ports_share_one_source_owner_but_keep_separate_returns_and_state(
    pool: PgPool,
) {
    let mut f = Fixture::stable(pool, "127.0.0.1".parse().unwrap()).await;
    let mut first = f.begin().await;
    let second = GoogleDesktopListener::bind("127.0.0.1".parse().unwrap(), f.uri().path())
        .await
        .unwrap();
    assert_ne!(
        second.redirect().as_str(),
        f.service.redirect(),
        "both listeners are owned concurrently"
    );
    let mut second = f.begin_on(second).await;
    let first_code = f.issue(&first, json!({})).await;
    let second_code = f.issue(&second, json!({})).await;
    let a = actor::command(&first, Some(&first_code), "callback", None);
    let b = actor::command(&second, Some(&second_code), "callback", None);
    let (first_owner, second_owner) = tokio::join!(
        async { f.commit(first.run_with(a, pending()).await.unwrap()).await },
        async { f.commit(second.run_with(b, pending()).await.unwrap()).await }
    );
    assert_eq!(first_owner.0, second_owner.0);
    assert_eq!(f.facts().await, (1, 1, 2, 2, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 2);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
    assert!(matches!(first.cancel().await, Err(Error::Unauthorized)));
    assert!(matches!(second.cancel().await, Err(Error::Unauthorized)));
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_wrong_exact_return_cannot_consume_or_cancel_another_port_attempt(pool: PgPool) {
    let mut f = Fixture::stable(pool, "127.0.0.1".parse().unwrap()).await;
    let mut first = f.begin().await;
    let listener = GoogleDesktopListener::bind("127.0.0.1".parse().unwrap(), f.uri().path())
        .await
        .unwrap();
    let second = f.begin_on(listener).await;
    let code = f.issue(&first, json!({})).await;
    let proof = || {
        OAuthBrowserProof::parse(
            first.start.transaction.proof.nonce().expose().to_owned(),
            first
                .start
                .transaction
                .proof
                .pkce_verifier()
                .expose()
                .to_owned(),
        )
        .unwrap()
    };
    let response = GoogleAuthorizationResponse::parse(&format!(
        "state={}&iss=https%3A%2F%2Faccounts.google.com&code={}",
        first.start.transaction.state.expose(),
        code.expose()
    ))
    .unwrap();
    assert!(matches!(
        first
            .service
            .finish(
                &first.intent(),
                &first.start.transaction.state,
                proof(),
                second.service.redirect(),
                response
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let intent = OAuthIntent {
        browser: &first.browser,
        source: SOURCE,
        purpose: OAuthPurpose::SignIn,
    };
    assert!(matches!(
        second
            .service
            .cancel(
                &intent,
                &first.start.transaction.state,
                &first.start.transaction.proof
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 2));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    second.cancel().await.unwrap();
    let command = actor::command(&first, Some(&code), "callback", None);
    f.commit(first.run_with(command, pending()).await.unwrap())
        .await;
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_stable_returns_do_not_bypass_actual_administrative_revision_changes(pool: PgPool) {
    let mut f = Fixture::stable(pool, "127.0.0.1".parse().unwrap()).await;
    let mut first = f.begin().await;
    let code = f.issue(&first, json!({})).await;
    let command = actor::command(&first, Some(&code), "callback", None);
    let (owner, old) = f
        .commit(first.run_with(command, pending()).await.unwrap())
        .await;
    f.reopen("127.0.0.1".parse().unwrap()).await;
    let mut pending_attempt = f.begin().await;
    let code = f.issue(&pending_attempt, json!({})).await;
    let command = actor::command(&pending_attempt, Some(&code), "callback", None);
    let GoogleAuthorizationCompletion::Verified(verified) =
        pending_attempt.run_with(command, pending()).await.unwrap()
    else {
        panic!("actual signed native proof required");
    };
    let mapped = f.policy.map(*verified).unwrap();
    f.policy = f
        .store
        .configure_oidc_identity_policy(&f.policy)
        .await
        .unwrap();
    assert!(matches!(
        f.store.authenticate(owner.realm_id, old.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        OidcSignIn::new(f.store.clone()).finish(mapped).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    f.reopen("127.0.0.1".parse().unwrap()).await;
    let mut current = f.begin().await;
    let code = f.issue(&current, json!({})).await;
    let command = actor::command(&current, Some(&code), "callback", None);
    let (same, _) = f
        .commit(current.run_with(command, pending()).await.unwrap())
        .await;
    assert_eq!(same, owner);
    assert_eq!(f.facts().await, (1, 1, 2, 2, 0));
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_profile_requires_bound_url_composition_instead_of_anchor_only_helpers(
    pool: PgPool,
) {
    let mut f = Fixture::stable(pool, "127.0.0.1".parse().unwrap()).await;
    let mut attempt = f.begin().await;
    let before = f.provider.document_gets.load(Ordering::SeqCst);
    let exchange = GoogleCodeExchange::new(
        f.policy.configuration().clone(),
        f.store.clone(),
        f.store.clone(),
        f.provider.authentication(),
        f.provider.clone(),
        f.provider.clone(),
    )
    .unwrap();
    assert!(matches!(
        exchange.authorization_url(&attempt.start.transaction).await,
        Err(Error::InvalidInput)
    ));
    let session_age = exchange.with_session_age_claims();
    assert!(matches!(
        session_age
            .authorization_url(&attempt.start.transaction)
            .await,
        Err(Error::InvalidInput)
    ));
    assert_eq!(f.provider.document_gets.load(Ordering::SeqCst), before);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    let code = f.issue(&attempt, json!({})).await;
    let command = actor::command(&attempt, Some(&code), "callback", None);
    f.commit(attempt.run_with(command, pending()).await.unwrap())
        .await;
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}
