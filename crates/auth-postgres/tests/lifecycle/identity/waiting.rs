use super::Fixture;
use crate::support::{challenge, reset_proof};
use auth_core::{Error, Repository};
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn email_free_revocation_rejects_a_changed_contact_snapshot_after_waiting(pool: PgPool) {
    let f = Fixture::new(pool.clone(), None).await;
    let (current, _) = f.session("passkey").await;
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(f.realm)
        .bind(f.user)
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let verifier = current.verifier();
    let realm = f.realm;
    let attempt = tokio::spawn(async move { store.revoke_all_sessions(realm, verifier).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%email IS NOT DISTINCT FROM%FOR UPDATE%')")
                .fetch_one(&pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    // Simulate the trusted final write of future mailbox attachment. This does
    // not claim that attachment's proof workflow is implemented yet.
    sqlx::query("UPDATE auth_users SET email='alice@example.com',email_verified_at=clock_timestamp() WHERE realm_id=$1 AND id=$2")
        .bind(f.realm).bind(f.user).execute(&mut *gate).await.unwrap();
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), attempt)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert!(
        f.store
            .authenticate(f.realm, current.verifier())
            .await
            .is_ok()
    );
    f.store
        .revoke_all_sessions(f.realm, current.verifier())
        .await
        .unwrap();
    assert!(
        f.store
            .authenticate(f.realm, current.verifier())
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn email_password_and_reset_recheck_policy_after_an_observed_user_lock_wait(pool: PgPool) {
    for mode in ["email", "password", "reset"] {
        let f = Fixture::new(pool.clone(), Some("alice@example.com")).await;
        sqlx::query(
            "UPDATE auth_users SET authentication_policy='mailbox' WHERE realm_id=$1 AND id=$2",
        )
        .bind(f.realm)
        .bind(f.user)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO auth_password_credentials(realm_id,user_id,password_hash) VALUES ($1,$2,'old-hash')")
            .bind(f.realm).bind(f.user).execute(&pool).await.unwrap();
        let (email, email_browser) = challenge(&f.store, f.realm, "alice@example.com").await;
        let (reset, reset_browser) = reset_proof(&f.store, f.realm, "alice@example.com").await;
        let mut gate = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
            .bind(f.realm)
            .bind(f.user)
            .execute(&mut *gate)
            .await
            .unwrap();
        let store = f.store.clone();
        let realm = f.realm;
        let attempt = tokio::spawn(async move {
            match mode {
                "email" => store
                    .finish_email(realm, email.verifier(), email_browser.verifier(), [1; 32])
                    .await
                    .map(|_| ()),
                "password" => {
                    store
                        .password_login(realm, "alice@example.com", "old-hash", [2; 32])
                        .await
                }
                _ => {
                    store
                        .finish_password_reset(
                            realm,
                            reset.verifier(),
                            reset_browser.verifier(),
                            "new-hash",
                        )
                        .await
                }
            }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%auth_users%')")
                    .fetch_one(&pool).await.unwrap();
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2")
            .bind(f.realm).bind(f.user).execute(&mut *gate).await.unwrap();
        gate.commit().await.unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), attempt)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::Unauthorized)
        ));
        let sessions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM auth_sessions WHERE realm_id=$1")
                .bind(f.realm)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(sessions, 0);
        let unchanged: String = sqlx::query_scalar(
            "SELECT password_hash FROM auth_password_credentials WHERE realm_id=$1 AND user_id=$2",
        )
        .bind(f.realm)
        .bind(f.user)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unchanged, "old-hash");
        let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE realm_id=$1")
            .bind(f.realm)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(audits, 0);
    }
}
