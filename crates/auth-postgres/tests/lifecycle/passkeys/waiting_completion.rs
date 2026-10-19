use super::*;
use auth_core::{Error, PasskeyRepository, Repository};
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn unchanged_pending_row_wait_cannot_extend_enrollment_expiry(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    let request = f.request(id);
    let state = f.store.load_enrollment(&request).await.unwrap();
    let encoded = state.encode_for_database().unwrap();
    let credential = f.service.verify_registration(&response, state).unwrap();
    expire_soon(&pool, id).await;
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_passkey_enrollments WHERE id=$1 FOR UPDATE")
        .bind(id)
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let finish = tokio::spawn(async move {
        store
            .commit_enrollment(&request, &encoded, credential)
            .await
    });
    wait_for_lock(
        &pool,
        "%SELECT label FROM auth_passkey_enrollments%FOR UPDATE%",
    )
    .await;
    wait_expired(&pool, id).await;
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), finish)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_rolled_back(&pool, f.realm, id).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn credential_uniqueness_wait_cannot_extend_enrollment_expiry(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let other = Fixture::new(pool.clone()).await;
    let other_owner = other
        .store
        .authenticate(other.realm, other.session.verifier())
        .await
        .unwrap()
        .id;
    let (id, response) = f.begin().await;
    let request = f.request(id);
    let state = f.store.load_enrollment(&request).await.unwrap();
    let encoded = state.encode_for_database().unwrap();
    let credential = f.service.verify_registration(&response, state).unwrap();
    let mut gate = pool.begin().await.unwrap();
    // Reserve the RP-wide unique credential in an uncommitted foreign account.
    // Rolling that row back lets insertion succeed, but cannot revive an expired proof.
    sqlx::query("INSERT INTO auth_passkeys(realm_id,id,user_id,rp_id,credential_id,credential,label) VALUES ($1,$2,$3,$4,$5,$6,'competing insertion')")
        .bind(other.realm).bind(Uuid::new_v4()).bind(other_owner)
        .bind(credential.rp_id()).bind(credential.credential_id()).bind(credential.encode_for_database().unwrap())
        .execute(&mut *gate).await.unwrap();
    expire_soon(&pool, id).await;
    let store = f.store.clone();
    let finish = tokio::spawn(async move {
        store
            .commit_enrollment(&request, &encoded, credential)
            .await
    });
    wait_for_lock(&pool, "%INSERT INTO auth_passkeys%").await;
    wait_expired(&pool, id).await;
    gate.rollback().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), finish)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_rolled_back(&pool, f.realm, id).await;
    let foreign_keys: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE realm_id=$1")
            .bind(other.realm)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(foreign_keys, 0);
}

async fn expire_soon(pool: &PgPool, id: Uuid) {
    sqlx::query("UPDATE auth_passkey_enrollments SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1")
        .bind(id).execute(pool).await.unwrap();
}

async fn wait_for_lock(pool: &PgPool, pattern: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)")
                .bind(pattern).fetch_one(pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
}

async fn wait_expired(pool: &PgPool, id: Uuid) {
    let query = "SELECT expires_at<=clock_timestamp() FROM auth_passkey_enrollments WHERE id=$1";
    assert!(
        !sqlx::query_scalar::<_, bool>(query)
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap(),
        "wait reached before deadline"
    );
    tokio::time::timeout(Duration::from_secs(8), async {
        while !sqlx::query_scalar::<_, bool>(query)
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

async fn assert_rolled_back(pool: &PgPool, realm: Uuid, pending: Uuid) {
    let keys: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE realm_id=$1")
        .bind(realm)
        .fetch_one(pool)
        .await
        .unwrap();
    let facts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_enrolled'",
    )
    .bind(realm)
    .fetch_one(pool)
    .await
    .unwrap();
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_passkey_enrollments WHERE realm_id=$1 AND id=$2",
    )
    .bind(realm)
    .bind(pending)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!((keys, facts, pending), (0, 0, 1));
}
