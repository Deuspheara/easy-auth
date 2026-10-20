use super::{delivery, setup::Fixture};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::{
    future::ready,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::Ordering,
};

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_owned_ipv4_ipv6_delivery_to_signed_exchange_and_commit_preserves_provider_ownership(
    pool: PgPool,
) {
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let mut f = Fixture::new(pool.clone(), ip).await;
        let (mailbox, old, email) = f.mailbox().await;
        let a = f
            .begin(json!({"email":email,"email_verified":true}), None)
            .await;
        let captured = delivery::capture(&mut f, &a, None).await;
        assert_eq!(
            f.facts().await,
            (1, 0, 1, 1, 1),
            "delivery alone cannot grant authority or consume state"
        );
        assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
        let completion = delivery::finish(&f, &a, captured).await.unwrap();
        let GoogleAuthorizationCompletion::Verified(identity) = &completion else {
            panic!("actual signed native positive control");
        };
        assert!(identity.expires_us() <= a.cap);
        assert_eq!(
            identity.authenticated_at(),
            None,
            "no native/browser freshness inference"
        );
        assert_eq!(
            f.facts().await,
            (1, 0, 1, 1, 0),
            "verified proof alone creates no local authority"
        );
        let (owner, session) = f.commit(completion).await;
        assert_ne!(
            owner.id, mailbox.id,
            "matching verified provider email cannot merge owners"
        );
        assert!(owner.email.is_none());
        assert_eq!(
            owner.authentication_policy,
            AuthenticationPolicy::ProviderRequired
        );
        assert_eq!(
            f.store
                .authenticate(f.realm(), session.verifier())
                .await
                .unwrap(),
            owner
        );
        assert_eq!(
            f.store
                .authenticate(f.realm(), old.verifier())
                .await
                .unwrap(),
            mailbox
        );
        assert_eq!(f.facts().await, (2, 1, 2, 2, 0));
        assert!(matches!(
            f.service
                .finish(
                    &a.intent(),
                    a.state(),
                    a.proof(),
                    f.policy.configuration().redirect(),
                    a.replay_response()
                )
                .await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
        assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    }
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_received_provider_denial_and_failure_cancel_only_bound_pending_state(pool: PgPool) {
    for error in ["access_denied", "server_error"] {
        let mut f = Fixture::new(pool.clone(), IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let (mailbox, session, _) = f.mailbox().await;
        let a = f.begin(json!({}), None).await;
        let captured = delivery::capture(&mut f, &a, Some(error)).await;
        assert_eq!(f.facts().await, (1, 0, 1, 1, 1));
        match delivery::finish(&f, &a, captured).await.unwrap() {
            GoogleAuthorizationCompletion::Denied => assert_eq!(error, "access_denied"),
            GoogleAuthorizationCompletion::ProviderFailure => assert_eq!(error, "server_error"),
            GoogleAuthorizationCompletion::Verified(_) => {
                panic!("native provider error cannot verify identity")
            }
        }
        assert_eq!(f.facts().await, (1, 0, 1, 1, 0));
        assert_eq!(
            f.store
                .authenticate(f.realm(), session.verifier())
                .await
                .unwrap(),
            mailbox
        );
        assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
        assert_eq!(f.provider.signed.load(Ordering::SeqCst), 0);
        f.rebind().await;
        let a = f.begin(json!({}), None).await;
        let captured = delivery::capture(&mut f, &a, None).await;
        f.commit(delivery::finish(&f, &a, captured).await.unwrap())
            .await;
        assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    }
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn native_transport_cancellation_requires_separate_original_proof_database_cancellation(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let a = f.begin(json!({}), None).await;
    assert!(matches!(
        f.listener
            .take()
            .unwrap()
            .receive(a.state(), a.cap, ready(()))
            .await,
        Err(easy_auth_server::GoogleDesktopError::Cancelled)
    ));
    assert_eq!(
        f.facts().await,
        (0, 0, 0, 0, 1),
        "transport cancellation is not database cancellation"
    );
    let wrong = OAuthBrowserProof::parse(
        Secret::generate().unwrap().expose().to_owned(),
        Secret::generate().unwrap().expose().to_owned(),
    )
    .unwrap();
    assert!(matches!(
        f.service.cancel(&a.intent(), a.state(), &wrong).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    f.service
        .cancel(&a.intent(), a.state(), &a.start.transaction.proof)
        .await
        .unwrap();
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    f.rebind().await;
    let a = f.begin(json!({}), None).await;
    let captured = delivery::capture(&mut f, &a, None).await;
    f.commit(delivery::finish(&f, &a, captured).await.unwrap())
        .await;
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
}
