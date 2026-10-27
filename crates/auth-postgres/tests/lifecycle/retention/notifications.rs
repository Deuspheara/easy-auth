use super::keeping;
use crate::support::{realm, signed_in};
use auth_core::{
    Repository, RetentionCategory, RetentionHorizon, RetentionPolicy, RetentionRepository,
};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

async fn enqueue(pool: &PgPool, realm: Uuid, user: Uuid, attempts: i32, old: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind,attempts,created_at) VALUES($1,$2,$3,'owned-notice@example.test','password_reset',$4,statement_timestamp()-make_interval(days=>$5))")
        .bind(realm).bind(id).bind(user).bind(attempts).bind(if old { 2 } else { 0 })
        .execute(pool).await.unwrap();
    id
}

#[sqlx::test(migrations = "./migrations")]
async fn explicit_exhaustion_age_preserves_real_worker_lease_retryable_recent_and_foreign_notices(
    pool: PgPool,
) {
    let (store, a) = realm(pool.clone()).await;
    let current = signed_in(&store, a, "owned-notice@example.test").await;
    let owner = store.authenticate(a, current.verifier()).await.unwrap().id;
    let leased = enqueue(&pool, a, owner, 7, true).await;
    let lease = store.claim_security_notice(a).await.unwrap().unwrap();
    assert_eq!(lease.id, leased);
    let retryable = enqueue(&pool, a, owner, 7, true).await;
    let recent = enqueue(&pool, a, owner, 8, false).await;
    let exhausted = enqueue(&pool, a, owner, 8, true).await;
    let b = Uuid::new_v4();
    store.ensure_realm(b).await.unwrap();
    let other = signed_in(&store, b, "owned-notice@example.test").await;
    let other_owner = store.authenticate(b, other.verifier()).await.unwrap().id;
    let foreign = enqueue(&pool, b, other_owner, 8, true).await;
    assert_eq!(
        store
            .retain_batch(a, RetentionCategory::Notifications, keeping())
            .await
            .unwrap()
            .deleted,
        0
    );
    let policy = RetentionPolicy::new(
        RetentionHorizon::keep(),
        RetentionHorizon::after(Duration::from_secs(86400)).unwrap(),
    );
    assert_eq!(
        store
            .retain_batch(a, RetentionCategory::Notifications, policy)
            .await
            .unwrap()
            .deleted,
        1
    );
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM auth_security_notifications")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(!ids.contains(&exhausted));
    for id in [leased, retryable, recent, foreign] {
        assert!(ids.contains(&id));
    }
    // The genuine current worker can still acknowledge the retained lease.
    store
        .complete_security_notice(a, lease.id, lease.lease, true)
        .await
        .unwrap();
    let alive: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth_security_notifications WHERE realm_id=$1 AND id=$2)",
    )
    .bind(a)
    .bind(leased)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!alive);
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_claim_cannot_cascade_a_leased_notice_or_reset_consumed_recovery_state(
    pool: PgPool,
) {
    let (store, a) = realm(pool.clone()).await;
    let current = signed_in(&store, a, "owned-recovery@example.test").await;
    let owner = store.authenticate(a, current.verifier()).await.unwrap().id;
    let claim = Uuid::new_v4();
    let version = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_passkey_recovery_codes(realm_id,user_id,rp_id,version,code_hash,consumed_at) VALUES($1,$2,'example.test',$3,decode(repeat('01',32),'hex'),statement_timestamp()-interval '8 days')")
        .bind(a).bind(owner).bind(version).execute(&pool).await.unwrap();
    // Privileged historical fixture, not a claim that eight days elapsed or a
    // production recovery-proof constructor. Existing consumed state is the asset.
    sqlx::query("INSERT INTO auth_passkey_recovery_claims(realm_id,user_id,rp_id,id,code_version,browser_hash,created_at,expires_at,delay_seconds,notification_required) VALUES($1,$2,'example.test',$3,$4,decode(repeat('02',32),'hex'),statement_timestamp()-interval '8 days',statement_timestamp()-interval '1 day',1,true)")
        .bind(a).bind(owner).bind(claim).bind(version).execute(&pool).await.unwrap();
    let notice = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind,recovery_claim_id) VALUES($1,$2,$3,'owned-recovery@example.test','passkey_recovery_started',$4)")
        .bind(a).bind(notice).bind(owner).bind(claim).execute(&pool).await.unwrap();
    let lease = store.claim_security_notice(a).await.unwrap().unwrap();
    assert_eq!(lease.id, notice);
    assert_eq!(
        store
            .retain_batch(a, RetentionCategory::RecoveryClaims, keeping())
            .await
            .unwrap()
            .deleted,
        0
    );
    assert_eq!(
        store
            .retain_batch(a, RetentionCategory::Notifications, keeping())
            .await
            .unwrap()
            .deleted,
        0
    );
    sqlx::query("UPDATE auth_security_notifications SET lease_until=statement_timestamp()-interval '1 second' WHERE realm_id=$1 AND id=$2")
        .bind(a).bind(notice).execute(&pool).await.unwrap();
    assert_eq!(
        store
            .retain_batch(a, RetentionCategory::Notifications, keeping())
            .await
            .unwrap()
            .deleted,
        1
    );
    assert_eq!(
        store
            .retain_batch(a, RetentionCategory::RecoveryClaims, keeping())
            .await
            .unwrap()
            .deleted,
        1
    );
    store
        .complete_security_notice(a, lease.id, lease.lease, true)
        .await
        .unwrap();
    let consumed: bool = sqlx::query_scalar("SELECT consumed_at IS NOT NULL AND version=$3 FROM auth_passkey_recovery_codes WHERE realm_id=$1 AND user_id=$2")
        .bind(a).bind(owner).bind(version).fetch_one(&pool).await.unwrap();
    assert!(consumed);
}
