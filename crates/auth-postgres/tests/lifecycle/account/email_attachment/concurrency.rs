use super::*;
use auth_core::Error;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_completion_has_one_rotated_session_and_one_fact(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (proof, browser) = f.proof("contact@example.com").await;
    let (a, b) = tokio::join!(
        f.store.finish_email_attachment(
            f.realm,
            f.current.verifier(),
            proof.verifier(),
            browser.verifier(),
            [8; 32]
        ),
        f.store.finish_email_attachment(
            f.realm,
            f.current.verifier(),
            proof.verifier(),
            browser.verifier(),
            [9; 32]
        )
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(f.audits().await, 1);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_sessions WHERE realm_id=$1 AND revoked_at IS NULL",
    )
    .bind(f.realm)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn already_owned_target_and_competing_owners_never_merge_accounts(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let existing = crate::support::signed_in(&f.store, f.realm, "owned@example.com").await;
    let owner = f
        .store
        .authenticate(f.realm, existing.verifier())
        .await
        .unwrap()
        .id;
    let (proof, browser) = f.proof("owned@example.com").await;
    assert!(matches!(
        f.store
            .finish_email_attachment(
                f.realm,
                f.current.verifier(),
                proof.verifier(),
                browser.verifier(),
                [8; 32]
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.email().await, None);
    assert_eq!(
        f.store
            .authenticate(f.realm, existing.verifier())
            .await
            .unwrap()
            .id,
        owner
    );
    let peer = Fixture::in_realm(pool.clone(), f.realm).await;
    let (a, ab) = f.proof("shared@example.com").await;
    let (b, bb) = peer.proof("shared@example.com").await;
    let (a, b) = tokio::join!(
        f.store.finish_email_attachment(
            f.realm,
            f.current.verifier(),
            a.verifier(),
            ab.verifier(),
            [8; 32]
        ),
        peer.store.finish_email_attachment(
            peer.realm,
            peer.current.verifier(),
            b.verifier(),
            bb.verifier(),
            [9; 32]
        )
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(f.audits().await, 1);
    assert_ne!(f.email().await.is_some(), peer.email().await.is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn both_mailbox_signup_attachment_orderings_preserve_one_address_owner(pool: PgPool) {
    for attachment_first in [false, true] {
        let f = Fixture::new(pool.clone()).await;
        let (proof, browser) = f.proof("race@example.com").await;
        let (mail, mail_browser) =
            crate::support::challenge(&f.store, f.realm, "race@example.com").await;
        let mut gate = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(5311)")
            .execute(&mut *gate)
            .await
            .unwrap();
        let kind = if attachment_first {
            "email_attached"
        } else {
            "email_authenticated"
        };
        sqlx::raw_sql(&format!("CREATE FUNCTION gate_attachment_order() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='{kind}' THEN PERFORM pg_advisory_xact_lock(5311); END IF; RETURN NEW; END $$; CREATE TRIGGER gate_attachment_order BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION gate_attachment_order();"))
            .execute(&pool).await.unwrap();
        let store = f.store.clone();
        let realm = f.realm;
        let current = f.current.verifier();
        let token = proof.verifier();
        let binding = browser.verifier();
        let mail_token = mail.verifier();
        let mail_binding = mail_browser.verifier();
        let first = tokio::spawn(async move {
            if attachment_first {
                store
                    .finish_email_attachment(realm, current, token, binding, [8; 32])
                    .await
            } else {
                store
                    .finish_email(realm, mail_token, mail_binding, [9; 32])
                    .await
                    .map(|_| ())
            }
        });
        wait_for(&pool,"SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=5311 AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT granted)").await;
        let store = f.store.clone();
        let second = tokio::spawn(async move {
            if attachment_first {
                store
                    .finish_email(realm, mail_token, mail_binding, [9; 32])
                    .await
                    .map(|_| ())
            } else {
                store
                    .finish_email_attachment(realm, current, token, binding, [8; 32])
                    .await
            }
        });
        wait_for(&pool,"SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%pg_advisory_xact_lock(hashtextextended%')").await;
        gate.commit().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), first)
                .await
                .unwrap()
                .unwrap()
                .is_ok()
        );
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), second)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::Unauthorized)
        ));
        assert_eq!(f.email().await.is_some(), attachment_first);
        sqlx::query("DROP TRIGGER gate_attachment_order ON auth_audit")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION gate_attachment_order()")
            .execute(&pool)
            .await
            .unwrap();
    }
}

async fn wait_for(pool: &PgPool, query: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if sqlx::query_scalar::<_, bool>(query)
                .fetch_one(pool)
                .await
                .unwrap()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
