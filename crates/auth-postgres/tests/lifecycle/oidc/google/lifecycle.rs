use super::setup::Fixture;
use crate::support::signed_in;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test(migrations = "./migrations")]
async fn google_https_and_loopback_metadata_code_commit_provider_only_owner_without_email_merge(
    pool: PgPool,
) {
    for desktop in [false, true] {
        let f = Fixture::new(pool.clone(), desktop, OidcJitPolicy::Allow).await;
        let old = signed_in(&f.store, f.realm(), "match@example.test").await;
        let mailbox = f
            .store
            .authenticate(f.realm(), old.verifier())
            .await
            .unwrap();
        let (user, session) = f
            .sign_in(
                f.mapped(
                    "same-subject",
                    json!({"email":"match@example.test","email_verified":true}),
                )
                .await,
            )
            .await
            .unwrap();
        assert_ne!(user.id, mailbox.id);
        assert_eq!(user.email, None);
        assert_eq!(
            user.authentication_policy,
            AuthenticationPolicy::ProviderRequired
        );
        assert_eq!(
            f.store
                .authenticate(f.realm(), session.verifier())
                .await
                .unwrap(),
            user
        );
        assert_eq!(
            f.store
                .authenticate(f.realm(), old.verifier())
                .await
                .unwrap(),
            mailbox
        );
        assert_eq!(f.facts().await, (2, 1, 2, 2, 0));
        let (same, _) = f
            .sign_in(
                f.mapped(
                    "same-subject",
                    json!({"email":"changed@example.test","email_verified":false}),
                )
                .await,
            )
            .await
            .unwrap();
        assert_eq!(
            same, user,
            "signed subject retains ownership despite changed email attribute"
        );
        assert_eq!(f.facts().await, (2, 1, 3, 3, 0));
        let page = f
            .store
            .list_sessions(f.realm(), session.verifier(), None)
            .await
            .unwrap();
        assert!(
            page.sessions
                .iter()
                .all(|s| s.authenticated_at_ms.is_none())
        );
        assert!(
            matches!(
                f.store
                    .revoke_all_sessions(f.realm(), session.verifier())
                    .await,
                Err(Error::Unauthorized)
            ),
            "token issuance cannot fabricate provider freshness"
        );
        assert_eq!(f.provider.posts.load(Ordering::SeqCst), 2);
        assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn google_jit_denial_is_after_verified_code_and_reconfiguration_preserves_existing_owner(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, false, OidcJitPolicy::Deny).await;
    let mapped = f.mapped("known", json!({})).await;
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert!(matches!(f.sign_in(mapped).await, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.reconfigure(OidcJitPolicy::Allow).await;
    let (owner, old) = f.sign_in(f.mapped("known", json!({})).await).await.unwrap();
    f.reconfigure(OidcJitPolicy::Deny).await;
    assert!(matches!(
        f.store.authenticate(f.realm(), old.verifier()).await,
        Err(Error::Unauthorized)
    ));
    let (same, _) = f.sign_in(f.mapped("known", json!({})).await).await.unwrap();
    assert_eq!(same, owner);
    assert!(matches!(
        f.sign_in(f.mapped("new-subject", json!({})).await).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (1, 1, 2, 2, 0));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 4);
}

#[sqlx::test(migrations = "./migrations")]
async fn owned_signed_authentication_time_does_not_rewrite_an_earlier_google_session(pool: PgPool) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let (_, old) = f
        .sign_in(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    // Genuine signature from the controlled offline provider, not evidence that
    // an actual registered Google client supplies this claim.
    let (_, fresh) = f
        .sign_in(f.mapped("subject", json!({"auth_time":now})).await)
        .await
        .unwrap();
    let page = f
        .store
        .list_sessions(f.realm(), fresh.verifier(), None)
        .await
        .unwrap();
    assert!(
        page.sessions
            .iter()
            .any(|s| s.authenticated_at_ms.is_none())
    );
    assert!(
        page.sessions
            .iter()
            .any(|s| s.authenticated_at_ms == Some(now * 1000))
    );
    assert!(matches!(
        f.store.revoke_all_sessions(f.realm(), old.verifier()).await,
        Err(Error::Unauthorized)
    ));
    f.store
        .revoke_all_sessions(f.realm(), fresh.verifier())
        .await
        .unwrap();
    for session in [old, fresh] {
        assert!(matches!(
            f.store.authenticate(f.realm(), session.verifier()).await,
            Err(Error::Unauthorized)
        ));
    }
}
