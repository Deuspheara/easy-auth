use super::setup::*;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn link_requires_original_session_not_another_fresh_session_of_the_same_owner(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (owner, original) = f.local("owner@example.test").await;
    let (_, replacement) = f.local("owner@example.test").await;
    let a = f
        .prepare(
            OAuthPurpose::Link {
                user: owner.id,
                session: original.verifier(),
            },
            "subject",
            json!({}),
        )
        .await;
    let before = f.facts().await;
    assert!(matches!(
        f.linking
            .finish(f.complete(&a).await.unwrap(), &replacement)
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, before);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    f.linked(&owner, &original, "subject").await;
    assert_eq!(
        f.store
            .authenticate(f.realm(), original.verifier())
            .await
            .unwrap(),
        owner
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_or_revoked_owner_cannot_prepare_or_finish_a_signed_link(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (owner, current) = f.local("owner@example.test").await;
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
    let mapped = f.complete(&a).await.unwrap();
    sqlx::query(
        "UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND token_hash=$2",
    )
    .bind(f.realm())
    .bind(current.verifier().as_slice())
    .execute(&f.pool)
    .await
    .unwrap();
    let before = f.facts().await;
    assert!(matches!(
        f.linking.finish(mapped, &current).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, before);
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "owned-social-linking",
        purpose: OAuthPurpose::Link {
            user: owner.id,
            session: current.verifier(),
        },
    };
    assert!(matches!(
        f.link.begin(&intent).await,
        Err(Error::Unauthorized)
    ));
    let (_, fresh) = f.local("owner@example.test").await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE realm_id=$1 AND token_hash=$2").bind(f.realm()).bind(fresh.verifier().as_slice()).execute(&f.pool).await.unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "owned-social-linking",
        purpose: OAuthPurpose::Link {
            user: owner.id,
            session: fresh.verifier(),
        },
    };
    assert!(matches!(
        f.link.begin(&intent).await,
        Err(Error::Unauthorized)
    ));
    let (_, fresh) = f.local("owner@example.test").await;
    f.linked(&owner, &fresh, "subject").await;
}

#[sqlx::test(migrations = "./migrations")]
async fn unlink_is_exact_owner_and_realm_scoped(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (owner, current) = f.local("owner@example.test").await;
    let linked = f.linked(&owner, &current, "subject").await;
    let (_, other) = f.local("other@example.test").await;
    let foreign = Fixture::new(pool).await;
    let (_, foreign_session) = foreign.local("owner@example.test").await;
    let before = f.facts().await;
    assert!(matches!(
        f.linking.unlink(f.realm(), &other, linked.id).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        foreign
            .linking
            .unlink(foreign.realm(), &foreign_session, linked.id)
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, before);
    f.linking
        .unlink(f.realm(), &current, linked.id)
        .await
        .unwrap();
}
