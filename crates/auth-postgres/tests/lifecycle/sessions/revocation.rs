use super::session;
use crate::support::{challenge, realm, reset_proof, signed_in};
use auth_core::{Error, Repository};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn individual_revocation_enforces_owner_realm_and_current_cookie_semantics(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let (target, target_id) = session(&pool, realm, user.id).await;
    let bob = signed_in(&store, realm, "bob@example.com").await;
    let bob_id: Uuid = sqlx::query_scalar("SELECT id FROM auth_sessions WHERE token_hash=$1")
        .bind(bob.verifier().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    let other_realm = Uuid::new_v4();
    store.ensure_realm(other_realm).await.unwrap();
    let foreign = signed_in(&store, other_realm, "alice@example.com").await;
    let foreign_id: Uuid = sqlx::query_scalar("SELECT id FROM auth_sessions WHERE token_hash=$1")
        .bind(foreign.verifier().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    let (_, expired_id) = session(&pool, realm, user.id).await;
    sqlx::query("UPDATE auth_sessions SET expires_at=clock_timestamp() WHERE id=$1")
        .bind(expired_id)
        .execute(&pool)
        .await
        .unwrap();
    for id in [bob_id, foreign_id, Uuid::new_v4(), expired_id] {
        assert!(
            !store
                .revoke_session(realm, current.verifier(), id)
                .await
                .unwrap()
        );
    }
    assert!(
        !store
            .revoke_session(realm, current.verifier(), target_id)
            .await
            .unwrap()
    );
    assert!(
        !store
            .revoke_session(realm, current.verifier(), target_id)
            .await
            .unwrap()
    );
    assert!(store.authenticate(realm, target.verifier()).await.is_err());
    assert!(store.authenticate(realm, bob.verifier()).await.is_ok());
    assert!(
        store
            .authenticate(other_realm, foreign.verifier())
            .await
            .is_ok()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='session_revoked'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let caller_id = store
        .list_sessions(realm, current.verifier(), None)
        .await
        .unwrap()
        .sessions[0]
        .id;
    assert!(
        store
            .revoke_session(realm, current.verifier(), caller_id)
            .await
            .unwrap()
    );
    assert!(store.authenticate(realm, current.verifier()).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn revocation_rechecks_freshness_idle_and_absolute_bounds(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let (target, target_id) = session(&pool, realm, user.id).await;
    for assignment in [
        "authenticated_at=clock_timestamp()-interval '5 minutes'",
        "authenticated_at=clock_timestamp()+interval '1 minute'",
        "authenticated_at='-infinity'",
        "last_seen_at=clock_timestamp()-interval '30 minutes'",
        "expires_at=clock_timestamp()",
    ] {
        let (invalid, id) = session(&pool, realm, user.id).await;
        sqlx::query(&format!(
            "UPDATE auth_sessions SET {assignment} WHERE id=$1"
        ))
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(matches!(
            store
                .revoke_session(realm, invalid.verifier(), target_id)
                .await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            store.revoke_all_sessions(realm, invalid.verifier()).await,
            Err(Error::Unauthorized)
        ));
    }
    assert!(store.authenticate(realm, target.verifier()).await.is_ok());
    // Inventory is not a sensitive mutation, so a valid session with old authentication still works.
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1")
        .bind(current.verifier().as_slice()).execute(&pool).await.unwrap();
    assert!(
        store
            .list_sessions(realm, current.verifier(), None)
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn revoke_all_cancels_owned_sessions_and_every_pending_proof(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let (second, _) = session(&pool, realm, user.id).await;
    let bob = signed_in(&store, realm, "bob@example.com").await;
    let (bob_mail, bob_browser) = challenge(&store, realm, "bob@example.com").await;
    reset_proof(&store, realm, "bob@example.com").await;
    store
        .begin_email_change(
            realm,
            bob.verifier(),
            "bob-new@example.com",
            [11; 32],
            [12; 32],
            [13; 32],
        )
        .await
        .unwrap();
    store
        .begin_account_deletion(realm, bob.verifier(), [14; 32], [15; 32])
        .await
        .unwrap();

    let (mail, browser) = challenge(&store, realm, "alice@example.com").await;
    reset_proof(&store, realm, "alice@example.com").await;
    store
        .begin_email_change(
            realm,
            current.verifier(),
            "new@example.com",
            [1; 32],
            [2; 32],
            [3; 32],
        )
        .await
        .unwrap();
    store
        .begin_account_deletion(realm, current.verifier(), [4; 32], [5; 32])
        .await
        .unwrap();
    let foreign_realm = Uuid::new_v4();
    store.ensure_realm(foreign_realm).await.unwrap();
    let foreign = signed_in(&store, foreign_realm, "alice@example.com").await;
    let (foreign_mail, foreign_browser) =
        challenge(&store, foreign_realm, "alice@example.com").await;
    store
        .revoke_all_sessions(realm, current.verifier())
        .await
        .unwrap();
    for secret in [&current, &second] {
        assert!(store.authenticate(realm, secret.verifier()).await.is_err());
    }
    assert!(
        store
            .finish_email(realm, mail.verifier(), browser.verifier(), [9; 32])
            .await
            .is_err()
    );
    for table in [
        "auth_email_challenges",
        "auth_password_resets",
        "auth_email_changes",
        "auth_account_deletions",
    ] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE realm_id=$1"))
            .bind(realm)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            n, 1,
            "only the other user’s pending proof remains in {table}"
        );
    }
    assert!(store.authenticate(realm, bob.verifier()).await.is_ok());
    assert!(
        store
            .finish_email(realm, bob_mail.verifier(), bob_browser.verifier(), [8; 32])
            .await
            .is_ok()
    );

    assert!(
        store
            .authenticate(foreign_realm, foreign.verifier())
            .await
            .is_ok()
    );
    assert!(
        store
            .finish_email(
                foreign_realm,
                foreign_mail.verifier(),
                foreign_browser.verifier(),
                [9; 32]
            )
            .await
            .is_ok()
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='all_sessions_revoked'",
    )
    .bind(realm)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn audit_failure_rolls_back_individual_and_all_revocation_and_proof_cleanup(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let (target, id) = session(&pool, realm, user.id).await;
    let (mail, browser) = challenge(&store, realm, "alice@example.com").await;
    reset_proof(&store, realm, "alice@example.com").await;
    sqlx::raw_sql("CREATE FUNCTION reject_revoke() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind IN ('session_revoked','all_sessions_revoked') THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_revoke BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION reject_revoke();")
        .execute(&pool).await.unwrap();
    assert!(
        store
            .revoke_session(realm, current.verifier(), id)
            .await
            .is_err()
    );
    assert!(store.authenticate(realm, target.verifier()).await.is_ok());
    assert!(
        store
            .revoke_all_sessions(realm, current.verifier())
            .await
            .is_err()
    );
    for s in [&current, &target] {
        assert!(store.authenticate(realm, s.verifier()).await.is_ok());
    }
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_password_resets WHERE realm_id=$1")
            .bind(realm)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pending, 1);
    assert!(
        store
            .finish_email(realm, mail.verifier(), browser.verifier(), [9; 32])
            .await
            .is_ok()
    );
}
