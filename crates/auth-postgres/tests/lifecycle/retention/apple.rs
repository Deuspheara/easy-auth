//! Ledger maintenance works in default builds without selecting an Apple worker.
//! Ciphertext strings here are opaque storage fixtures, never verified provider grants.
use super::keeping;
use crate::support::realm;
use auth_core::{RetentionCategory, RetentionRepository};
use sqlx::PgPool;
use uuid::Uuid;

async fn queued(
    pool: &PgPool,
    realm: Uuid,
    state: &str,
    attempts: i32,
    expiry: i32,
    lease: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_apple_grants(realm_id,id,connection_id,client_id,provider_client,binding_identity_id,key_id,ciphertext,state,attempts,created_at,queued_at,next_attempt_at,expires_at,lease_id,lease_until) VALUES($1,$2,gen_random_uuid(),gen_random_uuid(),'owned-client',gen_random_uuid(),gen_random_uuid(),'opaque-owned-storage',$3,$4,statement_timestamp()+make_interval(secs=>$5::integer)-interval '8 days',statement_timestamp()+make_interval(secs=>$5::integer)-interval '7 days',statement_timestamp()-interval '1 second',statement_timestamp()+make_interval(secs=>$5::integer),CASE WHEN $3='leased' THEN gen_random_uuid() END,CASE WHEN $3='leased' THEN statement_timestamp()+make_interval(secs=>$6::integer) END)")
        .bind(realm).bind(id).bind(state).bind(attempts).bind(expiry).bind(lease)
        .execute(pool).await.unwrap();
    id
}

async fn terminal(pool: &PgPool, realm: Uuid, state: &str, days: i32) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_apple_grants(realm_id,id,connection_id,client_id,provider_client,binding_identity_id,state,attempts,created_at,queued_at,expires_at,finished_at,failure) VALUES($1,$2,gen_random_uuid(),gen_random_uuid(),'owned-client',gen_random_uuid(),$3,1,statement_timestamp()-interval '16 days',statement_timestamp()-interval '15 days',statement_timestamp()-interval '8 days',statement_timestamp()-make_interval(days=>$4),CASE WHEN $3='expired' THEN 'expired' END)")
        .bind(realm).bind(id).bind(state).bind(days).execute(pool).await.unwrap();
    id
}

#[sqlx::test(migrations = "./migrations")]
async fn common_maintenance_counts_distinct_effects_and_preserves_live_leases_and_foreign_ciphertext(
    pool: PgPool,
) {
    let (store, a) = realm(pool.clone()).await;
    let b = Uuid::new_v4();
    store.ensure_realm(b).await.unwrap();
    let expired = queued(&pool, a, "pending", 0, -1, 0).await;
    let pending = queued(&pool, a, "pending", 0, 3600, 0).await;
    let exhausted = queued(&pool, a, "leased", 8, 3600, -1).await;
    let leased = queued(&pool, a, "leased", 8, 3600, 30).await;
    let foreign = queued(&pool, b, "pending", 0, -1, 0).await;
    let old = terminal(&pool, a, "completed", 8).await;
    let recent = terminal(&pool, a, "expired", 1).await;
    let effects = store
        .retain_batch(a, RetentionCategory::AppleGrants, keeping())
        .await
        .unwrap();
    assert_eq!(
        (
            effects.deleted,
            effects.expired_ciphertexts,
            effects.exhausted_leases
        ),
        (1, 1, 1)
    );
    for (id, expected_state, erased, has_lease) in [
        (expired, "expired", true, false),
        (pending, "pending", false, false),
        (exhausted, "failed", false, false),
        (leased, "leased", false, true),
        (foreign, "pending", false, false),
        (recent, "expired", true, false),
    ] {
        let actual: (String,bool,bool) = sqlx::query_as("SELECT state,ciphertext IS NULL AND key_id IS NULL,lease_id IS NOT NULL FROM auth_apple_grants WHERE id=$1")
            .bind(id).fetch_one(&pool).await.unwrap();
        assert_eq!(actual, (expected_state.into(), erased, has_lease));
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_apple_grants WHERE id=$1)")
            .bind(old)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!exists);
    let rerun = store
        .retain_batch(a, RetentionCategory::AppleGrants, keeping())
        .await
        .unwrap();
    assert_eq!(rerun, auth_core::RetentionBatch::default());
}
