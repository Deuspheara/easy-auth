mod concurrency;
mod inventory;
mod migration;
mod revocation;

use crate::support::*;
use auth_core::{Repository, Secret};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn expiry_and_idle_limits_cannot_be_revived(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let (token, browser) = challenge(&store, realm, "alice@example.com").await;
    sqlx::query("UPDATE auth_email_challenges SET expires_at=now()-interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        store
            .finish_email(realm, token.verifier(), browser.verifier(), [7; 32])
            .await
            .is_err()
    );
    for update in [
        "UPDATE auth_sessions SET last_seen_at=now()-interval '31 minutes'",
        "UPDATE auth_sessions SET expires_at=now()-interval '1 second'",
    ] {
        let (token, browser) = challenge(&store, realm, "alice@example.com").await;
        let session = Secret::generate().unwrap();
        store
            .finish_email(
                realm,
                token.verifier(),
                browser.verifier(),
                session.verifier(),
            )
            .await
            .unwrap();
        sqlx::query(update).execute(&pool).await.unwrap();
        assert!(store.authenticate(realm, session.verifier()).await.is_err());
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn composite_foreign_keys_reject_cross_tenant_users(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let (token, browser) = challenge(&store, realm, "alice@example.com").await;
    let user = store
        .finish_email(realm, token.verifier(), browser.verifier(), [2; 32])
        .await
        .unwrap();
    let other = Uuid::new_v4();
    store.ensure_realm(other).await.unwrap();
    let result = sqlx::query(
        "INSERT INTO auth_sessions(realm_id,id,user_id,token_hash) VALUES ($1,$2,$3,$4)",
    )
    .bind(other)
    .bind(Uuid::new_v4())
    .bind(user.id)
    .bind([0u8; 32].as_slice())
    .execute(&pool)
    .await;
    assert!(result.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn password_enrollment_rotation_preserves_authentication_time(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes' WHERE token_hash=$1").bind(current.verifier().as_slice()).execute(&pool).await.unwrap();
    store
        .enroll_password(realm, current.verifier(), "hash", [1; 32])
        .await
        .unwrap();
    let preserved:bool=sqlx::query_scalar("SELECT authenticated_at<clock_timestamp()-interval '3 minutes' FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2").bind(realm).bind([1u8;32].as_slice()).fetch_one(&pool).await.unwrap();
    assert!(preserved);
}

// Seed additional issued sessions without exercising unrelated mail-admission limits.
pub(super) async fn session(pool: &PgPool, realm: Uuid, user: Uuid) -> (Secret, Uuid) {
    let secret = Secret::generate().unwrap();
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash) VALUES ($1,$2,$3,$4)")
        .bind(realm)
        .bind(id)
        .bind(user)
        .bind(secret.verifier().as_slice())
        .execute(pool)
        .await
        .unwrap();
    (secret, id)
}
