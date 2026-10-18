use super::{rows, session_id};
use crate::support::{realm, reset_proof, signed_in};
use auth_core::{Repository, Secret};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn real_lifecycle_events_are_attributed_redacted_and_erased_without_touching_other_users(
    pool: PgPool,
) {
    let (store, realm) = realm(pool.clone()).await;
    let email = "audit-alice@example.com";
    let first = signed_in(&store, realm, email).await;
    let user = store.authenticate(realm, first.verifier()).await.unwrap();
    let first_id = session_id(&pool, first.verifier()).await;
    let bob = signed_in(&store, realm, "audit-bob@example.com").await;
    let bob_user = store.authenticate(realm, bob.verifier()).await.unwrap();
    // This repository test receives already-verified credential strings from the core port.
    let hash = "synthetic-credential-canary-before-reset";
    let new_hash = "synthetic-credential-canary-after-reset";
    let replacement = Secret::generate().unwrap();
    store
        .enroll_password(realm, first.verifier(), hash, replacement.verifier())
        .await
        .unwrap();
    let replacement_id = session_id(&pool, replacement.verifier()).await;
    let enrolled:(uuid::Uuid,uuid::Uuid,uuid::Uuid,i16)=sqlx::query_as("SELECT user_id,actor_session_id,session_id,schema_version FROM auth_audit WHERE realm_id=$1 AND kind='password_enrolled'")
        .bind(realm).fetch_one(&pool).await.unwrap();
    assert_eq!(enrolled, (user.id, first_id, replacement_id, 1));
    let login = Secret::generate().unwrap();
    store
        .password_login(realm, email, hash, login.verifier())
        .await
        .unwrap();
    store.revoke(realm, replacement.verifier()).await.unwrap();
    let (reset, browser) = reset_proof(&store, realm, email).await;
    store
        .finish_password_reset(realm, reset.verifier(), browser.verifier(), new_hash)
        .await
        .unwrap();
    let recovered = Secret::generate().unwrap();
    store
        .password_login(realm, email, new_hash, recovered.verifier())
        .await
        .unwrap();
    let old = Secret::generate().unwrap();
    let new = Secret::generate().unwrap();
    let binding = Secret::generate().unwrap();
    store
        .begin_email_change(
            realm,
            recovered.verifier(),
            "audit-changed@example.com",
            old.verifier(),
            new.verifier(),
            binding.verifier(),
        )
        .await
        .unwrap();
    assert!(
        !store
            .confirm_email_change(
                realm,
                recovered.verifier(),
                old.verifier(),
                binding.verifier()
            )
            .await
            .unwrap()
    );
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='email_changed'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pending, 0);
    assert!(
        store
            .confirm_email_change(
                realm,
                recovered.verifier(),
                new.verifier(),
                binding.verifier()
            )
            .await
            .unwrap()
    );
    let changed = Secret::generate().unwrap();
    store
        .password_login(
            realm,
            "audit-changed@example.com",
            new_hash,
            changed.verifier(),
        )
        .await
        .unwrap();
    store
        .revoke_all_sessions(realm, changed.verifier())
        .await
        .unwrap();
    let last = Secret::generate().unwrap();
    store
        .password_login(
            realm,
            "audit-changed@example.com",
            new_hash,
            last.verifier(),
        )
        .await
        .unwrap();
    let all = rows(&pool, realm).await.join("\n");
    for value in [email, "audit-changed@example.com", hash, new_hash] {
        assert!(!all.contains(value));
    }
    for secret in [
        &first,
        &replacement,
        &login,
        &reset,
        &browser,
        &recovered,
        &old,
        &new,
        &binding,
        &changed,
        &last,
        &bob,
    ] {
        assert!(!all.contains(secret.expose()));
        let hex: String = secret
            .verifier()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!all.contains(&hex));
    }
    let invalid:i64=sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND (schema_version<>1 OR subject_erased)")
        .bind(realm).fetch_one(&pool).await.unwrap();
    assert_eq!(invalid, 0);
    let token = Secret::generate().unwrap();
    let delete_browser = Secret::generate().unwrap();
    store
        .begin_account_deletion(
            realm,
            last.verifier(),
            token.verifier(),
            delete_browser.verifier(),
        )
        .await
        .unwrap();
    store
        .finish_account_deletion(
            realm,
            last.verifier(),
            token.verifier(),
            delete_browser.verifier(),
        )
        .await
        .unwrap();
    let residual:i64=sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND (user_id=$2 OR (subject_erased AND (user_id IS NOT NULL OR actor_session_id IS NOT NULL OR session_id IS NOT NULL)))")
        .bind(realm).bind(user.id).fetch_one(&pool).await.unwrap();
    assert_eq!(residual, 0);
    let deidentified: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND subject_erased")
            .bind(realm)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(deidentified >= 8);
    let kinds: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT kind FROM auth_audit WHERE realm_id=$1 ORDER BY kind")
            .bind(realm)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        kinds,
        vec![
            "account_deleted",
            "all_sessions_revoked",
            "email_authenticated",
            "email_changed",
            "password_authenticated",
            "password_enrolled",
            "password_reset",
            "session_revoked"
        ]
    );
    let preserved:(uuid::Uuid,Option<uuid::Uuid>,Option<uuid::Uuid>,bool)=sqlx::query_as("SELECT user_id,actor_session_id,session_id,subject_erased FROM auth_audit WHERE realm_id=$1 AND user_id=$2")
        .bind(realm).bind(bob_user.id).fetch_one(&pool).await.unwrap();
    assert_eq!(
        preserved,
        (
            bob_user.id,
            None,
            Some(session_id(&pool, bob.verifier()).await),
            false
        )
    );
    assert!(store.authenticate(realm, bob.verifier()).await.is_ok());
    let erased = rows(&pool, realm).await.join("\n");
    assert!(!erased.contains(&user.id.to_string()));
}
