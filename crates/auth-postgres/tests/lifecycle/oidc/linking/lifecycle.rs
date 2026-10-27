use super::setup::*;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn explicit_link_preserves_owner_and_contact_even_when_provider_email_matches_another_account(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (owner, current) = f.local("owner@example.test").await;
    let (other, other_session) = f.local("other@example.test").await;
    let a = f
        .prepare(
            OAuthPurpose::Link {
                user: owner.id,
                session: current.verifier(),
            },
            "subject",
            json!({"email":"other@example.test","email_verified":"true"}),
        )
        .await;
    let linked = f
        .linking
        .finish(f.complete(&a).await.unwrap(), &current)
        .await
        .unwrap();
    assert_eq!(linked.kind, ProviderKind::Oidc);
    assert_eq!(f.facts().await, (2, 1, 2, 3, 1));
    let (signed_in, provider_session) = f.login("subject").await.unwrap();
    assert_eq!(signed_in, owner);
    assert_ne!(signed_in.id, other.id);
    assert_eq!(
        f.store
            .authenticate(f.realm(), provider_session.verifier())
            .await
            .unwrap(),
        owner
    );
    assert_eq!(
        f.store
            .authenticate(f.realm(), other_session.verifier())
            .await
            .unwrap(),
        other
    );
    let recipient:String=sqlx::query_scalar("SELECT recipient FROM auth_security_notifications WHERE realm_id=$1 AND kind='providers_changed'").bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(recipient, "owner@example.test");
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn unlink_revokes_and_detaches_provider_sessions_without_erasing_audit_or_retained_method(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (owner, current) = f.local("owner@example.test").await;
    let linked = f.linked(&owner, &current, "subject").await;
    let (_, provider_session) = f.login("subject").await.unwrap();
    let before = f.facts().await;
    f.linking
        .unlink(f.realm(), &current, linked.id)
        .await
        .unwrap();
    assert_eq!(
        f.store
            .authenticate(f.realm(), current.verifier())
            .await
            .unwrap(),
        owner
    );
    assert!(matches!(
        f.store
            .authenticate(f.realm(), provider_session.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    let detached:(String,bool,Option<uuid::Uuid>)=sqlx::query_as("SELECT authentication_method,revoked_at IS NOT NULL,oidc_identity_id FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2").bind(f.realm()).bind(provider_session.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(detached, ("oidc".to_owned(), true, None));
    let after = f.facts().await;
    assert_eq!(after, (before.0, 0, before.2, before.3 + 1, before.4 + 1));
    assert!(matches!(f.login("subject").await, Err(Error::Unauthorized)));
    let a = f
        .prepare(
            OAuthPurpose::Link {
                user: owner.id,
                session: current.verifier(),
            },
            "subject",
            json!({}),
        )
        .await;
    assert!(matches!(
        f.linking
            .finish(f.complete(&a).await.unwrap(), &current)
            .await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn linking_proofs_cannot_sign_in_and_signin_proofs_cannot_link(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (owner, current) = f.local("owner@example.test").await;
    let purpose = OAuthPurpose::Link {
        user: owner.id,
        session: current.verifier(),
    };
    let a = f.prepare(purpose.clone(), "subject", json!({})).await;
    assert!(matches!(
        f.signin
            .finish(
                &a.intent(),
                &a.start.transaction.state,
                a.proof(),
                f.policy.configuration().redirect(),
                a.response()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let mapped = f.complete(&a).await.unwrap();
    assert!(matches!(
        OidcSignIn::new(f.store.clone()).finish(mapped).await,
        Err(Error::Unauthorized)
    ));
    let a = f.prepare(OAuthPurpose::SignIn, "subject", json!({})).await;
    assert!(matches!(
        f.link.begin(&a.intent()).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.linking
            .finish(f.complete(&a).await.unwrap(), &current)
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (1, 0, 1, 1, 0));
}
