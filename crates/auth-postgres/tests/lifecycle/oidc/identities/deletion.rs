use super::setup::{Fixture, wait_for_lock};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

// Owned persistence fixture: provider-only deletion has no new public endpoint.
// Follow the existing owner lock and audit-erasure contract, including cascades.
async fn delete(pool: PgPool, realm: Uuid, user: Uuid) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(realm)
        .bind(user)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    erase(&mut tx, realm, user).await;
    sqlx::query("DELETE FROM auth_users WHERE realm_id=$1 AND id=$2")
        .bind(realm)
        .bind(user)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}
async fn erase(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, realm: Uuid, user: Uuid) {
    sqlx::query("UPDATE auth_audit SET user_id=NULL,actor_session_id=NULL,session_id=NULL,passkey_id=NULL,recovery_claim_id=NULL,subject_erased=true WHERE realm_id=$1 AND user_id=$2")
        .bind(realm).bind(user).execute(&mut **tx).await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn deleted_subject_cooldown_and_original_deadlines_prevent_anonymous_jit_resurrection(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (original, old_session) = f
        .sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    let first = f
        .mapped_for("subject", json!({}), OAuthPurpose::SignIn, Some(2))
        .await;
    let second = f
        .mapped_for("subject", json!({}), OAuthPurpose::SignIn, Some(2))
        .await;
    let cap = second.identity().expires_us();
    delete(f.pool.clone(), f.realm(), original.id).await;
    let cleanup = f
        .store
        .retain_batch(
            f.realm(),
            RetentionCategory::OidcCooldowns,
            RetentionPolicy::new(RetentionHorizon::keep(), RetentionHorizon::keep()),
        )
        .await
        .unwrap();
    assert_eq!(
        cleanup.deleted, 0,
        "maintenance preserves the original callback cooldown"
    );
    let remaining: f64 = sqlx::query_scalar("SELECT extract(epoch FROM blocked_until-clock_timestamp())::float8 FROM auth_oidc_deleted_subjects").fetch_one(&f.pool).await.unwrap();
    assert!(
        remaining > 298.0 && remaining <= 300.0,
        "actual deletion installs the unchanged five-minute cooldown"
    );
    assert!(matches!(
        f.sign_in.finish(first).await,
        Err(Error::Unauthorized)
    ));
    assert!(
        matches!(
            f.sign_in.finish(f.mapped("subject", json!({})).await).await,
            Err(Error::Unauthorized)
        ),
        "fresh requests also respect deletion cooldown"
    );
    assert!(matches!(
        f.store
            .authenticate(f.realm(), old_session.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    f.wait_for_expiry(cap).await;
    // Privileged retention fixture, not elapsed five-minute/device evidence.
    sqlx::query(
        "UPDATE auth_oidc_deleted_subjects SET blocked_until=clock_timestamp()-interval '1 second'",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(
        matches!(f.sign_in.finish(second).await, Err(Error::Unauthorized)),
        "expired original proof cannot revive after tombstone cleanup"
    );
    let (fresh, _) = f
        .sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    assert_ne!(fresh.id, original.id);
    let retained: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_oidc_deleted_subjects")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(retained, 0);
    assert_eq!(f.facts().await, (1, 1, 1, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn deletion_winning_owner_lock_rejects_waiting_proof_without_falling_through_to_jit(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (user, _) = f
        .sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    let mapped = f.mapped("subject", json!({})).await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(f.realm())
        .bind(user.id)
        .fetch_one(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let action = tokio::spawn(async move { OidcSignIn::new(store).finish(mapped).await });
    wait_for_lock(&f.pool, "%email IS NOT DISTINCT FROM%FOR UPDATE%").await;
    erase(&mut gate, f.realm(), user.id).await;
    sqlx::query("DELETE FROM auth_users WHERE realm_id=$1 AND id=$2")
        .bind(f.realm())
        .bind(user.id)
        .execute(&mut *gate)
        .await
        .unwrap();
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("test infrastructure: deleted-owner callback finishes")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (0, 0, 0, 1, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn callback_winning_owner_lock_can_commit_before_deletion_erases_its_new_authority(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (user, _) = f
        .sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    let mapped = f.mapped("subject", json!({})).await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_audit IN SHARE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let callback = tokio::spawn(async move { OidcSignIn::new(store).finish(mapped).await });
    wait_for_lock(&f.pool, "%INSERT INTO auth_audit%").await;
    let pool = f.pool.clone();
    let realm = f.realm();
    let deleting = tokio::spawn(async move { delete(pool, realm, user.id).await });
    wait_for_lock(&f.pool, "%SELECT id FROM auth_users%FOR UPDATE%").await;
    gate.commit().await.unwrap();
    let (_, session) = tokio::time::timeout(Duration::from_secs(5), callback)
        .await
        .expect("test infrastructure: callback finishes before deletion")
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), deleting)
        .await
        .expect("test infrastructure: waiting deletion finishes")
        .unwrap();
    assert!(matches!(
        f.store.authenticate(f.realm(), session.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
}
