use super::setup::*;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_owners_cannot_link_the_same_scoped_subject(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (one, first) = f.local("one@example.test").await;
    let (two, second) = f.local("two@example.test").await;
    let a = f
        .prepare(
            OAuthPurpose::Link {
                user: one.id,
                session: first.verifier(),
            },
            "subject",
            json!({}),
        )
        .await;
    let b = f
        .prepare(
            OAuthPurpose::Link {
                user: two.id,
                session: second.verifier(),
            },
            "subject",
            json!({}),
        )
        .await;
    let a = f.complete(&a).await.unwrap();
    let b = f.complete(&b).await.unwrap();
    let (a, b) = tokio::join!(f.linking.finish(a, &first), f.linking.finish(b, &second));
    assert!(matches!(
        (a, b),
        (Ok(_), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(_))
    ));
    assert_eq!(f.facts().await, (2, 1, 2, 3, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn link_notice_failure_restores_identity_audit_and_notice_but_not_consumed_state(
    pool: PgPool,
) {
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
    sqlx::raw_sql("CREATE FUNCTION reject_link_notice() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned link notice fault'; END $$; CREATE TRIGGER reject_link_notice BEFORE INSERT ON auth_security_notifications FOR EACH ROW EXECUTE FUNCTION reject_link_notice();").execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.linking.finish(mapped, &current).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.facts().await, (1, 0, 1, 1, 0));
    assert!(matches!(f.complete(&a).await, Err(Error::Unauthorized)));
    sqlx::query("DROP TRIGGER reject_link_notice ON auth_security_notifications")
        .execute(&f.pool)
        .await
        .unwrap();
    f.linked(&owner, &current, "subject").await;
}

#[sqlx::test(migrations = "./migrations")]
async fn unlink_notice_failure_restores_binding_sessions_and_audit_history(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (owner, current) = f.local("owner@example.test").await;
    let linked = f.linked(&owner, &current, "subject").await;
    let (_, provider_session) = f.login("subject").await.unwrap();
    let before = f.facts().await;
    sqlx::raw_sql("CREATE FUNCTION reject_unlink_notice() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned unlink notice fault'; END $$; CREATE TRIGGER reject_unlink_notice BEFORE INSERT ON auth_security_notifications FOR EACH ROW EXECUTE FUNCTION reject_unlink_notice();").execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.linking.unlink(f.realm(), &current, linked.id).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.facts().await, before);
    assert_eq!(
        f.store
            .authenticate(f.realm(), provider_session.verifier())
            .await
            .unwrap(),
        owner
    );
    sqlx::query("DROP TRIGGER reject_unlink_notice ON auth_security_notifications")
        .execute(&f.pool)
        .await
        .unwrap();
    f.linking
        .unlink(f.realm(), &current, linked.id)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn target_disable_during_link_token_io_rejects_the_actual_late_signature(pool: PgPool) {
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
    f.provider.hold.store(true, Ordering::SeqCst);
    let completion = f.complete(&a);
    let disable = async {
        tokio::time::timeout(Duration::from_secs(5), f.provider.entered.notified())
            .await
            .expect("owned actual Apple credential/code POST entered");
        let c = f.policy.configuration();
        f.store
            .disable_oauth_connection(c.realm(), c.connection(), c.client())
            .await
            .unwrap();
        f.provider.release.notify_one();
    };
    let (result, ()) = tokio::join!(completion, disable);
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (1, 0, 1, 1, 0));
    assert_eq!(
        f.store
            .authenticate(f.realm(), current.verifier())
            .await
            .unwrap(),
        owner
    );
}
