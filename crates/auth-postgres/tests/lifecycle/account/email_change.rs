use super::change_proofs;
use crate::support::*;
use auth_core::Repository;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn email_change_requires_both_mailboxes_and_same_fresh_session(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let other_session = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let (old, new, browser) =
        change_proofs(&store, realm, current.verifier(), "new@example.com").await;
    assert!(
        store
            .confirm_email_change(
                realm,
                other_session.verifier(),
                old.verifier(),
                browser.verifier()
            )
            .await
            .is_err()
    );
    assert!(
        store
            .confirm_email_change(realm, current.verifier(), old.verifier(), [0; 32])
            .await
            .is_err()
    );
    let other = Uuid::new_v4();
    store.ensure_realm(other).await.unwrap();
    assert!(
        store
            .confirm_email_change(
                other,
                current.verifier(),
                old.verifier(),
                browser.verifier()
            )
            .await
            .is_err()
    );
    assert!(
        !store
            .confirm_email_change(
                realm,
                current.verifier(),
                new.verifier(),
                browser.verifier()
            )
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .authenticate(realm, current.verifier())
            .await
            .unwrap()
            .email
            .as_deref(),
        Some("alice@example.com")
    );
    assert!(
        store
            .confirm_email_change(
                realm,
                current.verifier(),
                new.verifier(),
                browser.verifier()
            )
            .await
            .is_err()
    );
    assert!(
        store
            .confirm_email_change(
                realm,
                current.verifier(),
                old.verifier(),
                browser.verifier()
            )
            .await
            .unwrap()
    );
    assert!(store.authenticate(realm, current.verifier()).await.is_err());
    assert!(
        store
            .authenticate(realm, other_session.verifier())
            .await
            .is_err()
    );
    let signed = signed_in(&store, realm, "new@example.com").await;
    let changed = store.authenticate(realm, signed.verifier()).await.unwrap();
    assert_eq!(changed.id, user.id);
    assert!(
        store
            .confirm_email_change(realm, signed.verifier(), old.verifier(), browser.verifier())
            .await
            .is_err()
    );
    let notice = store.claim_security_notice(realm).await.unwrap().unwrap();
    assert_eq!(notice.recipient, "alice@example.com");
    // Session creation and last-seen do not extend the authentication freshness window.
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes',created_at=clock_timestamp(),last_seen_at=clock_timestamp() WHERE token_hash=$1").bind(signed.verifier().as_slice()).execute(&pool).await.unwrap();
    assert!(
        store
            .begin_email_change(
                realm,
                signed.verifier(),
                "next@example.com",
                [1; 32],
                [2; 32],
                [3; 32]
            )
            .await
            .is_err()
    );
    assert!(
        store
            .begin_account_deletion(realm, signed.verifier(), [1; 32], [2; 32])
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn email_uniqueness_race_never_merges_accounts(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let a = signed_in(&store, realm, "a@example.com").await;
    let b = signed_in(&store, realm, "b@example.com").await;
    let ua = store.authenticate(realm, a.verifier()).await.unwrap();
    let ub = store.authenticate(realm, b.verifier()).await.unwrap();
    let (oa, na, ba) = change_proofs(&store, realm, a.verifier(), "target@example.com").await;
    let (ob, nb, bb) = change_proofs(&store, realm, b.verifier(), "target@example.com").await;
    assert!(
        !store
            .confirm_email_change(realm, a.verifier(), oa.verifier(), ba.verifier())
            .await
            .unwrap()
    );
    assert!(
        !store
            .confirm_email_change(realm, b.verifier(), ob.verifier(), bb.verifier())
            .await
            .unwrap()
    );
    let (ra, rb) = tokio::join!(
        store.confirm_email_change(realm, a.verifier(), na.verifier(), ba.verifier()),
        store.confirm_email_change(realm, b.verifier(), nb.verifier(), bb.verifier())
    );
    assert_eq!(
        usize::from(matches!(ra, Ok(true))) + usize::from(matches!(rb, Ok(true))),
        1
    );
    let target: Uuid = sqlx::query_scalar(
        "SELECT id FROM auth_users WHERE realm_id=$1 AND email='target@example.com'",
    )
    .bind(realm)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(target == ua.id || target == ub.id);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_users WHERE realm_id=$1")
        .bind(realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
}
