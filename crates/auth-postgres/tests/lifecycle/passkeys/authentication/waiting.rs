use super::*;
use auth_core::Error;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn ceremony_expiry_is_checked_after_a_lock_wait_without_row_updates(pool: PgPool) {
    let mut f = SignIn::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    sqlx::query("UPDATE auth_passkey_authentications SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1")
        .bind(id).execute(&pool).await.unwrap();
    let proof = f.proof(id, &response).await;
    let session = Secret::generate().unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_passkey_authentications WHERE id=$1 FOR UPDATE")
        .bind(id)
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.enrollment.store.clone();
    let request = f.request(id);
    let verifier = session.verifier();
    let finish =
        tokio::spawn(async move { store.commit_authentication(&request, proof, verifier).await });
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id FROM auth_passkey_authentications%FOR UPDATE%')").fetch_one(&pool).await.unwrap();
            if waiting { break; } tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    let live: bool = sqlx::query_scalar(
        "SELECT expires_at>clock_timestamp() FROM auth_passkey_authentications WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(live, "commit reached the row lock before expiry");
    tokio::time::timeout(Duration::from_secs(8),async {
        loop {
            let expired:bool=sqlx::query_scalar("SELECT expires_at<=clock_timestamp() FROM auth_passkey_authentications WHERE id=$1")
                .bind(id).fetch_one(&pool).await.unwrap();
            if expired { break; } tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.unwrap();
    // No UPDATE while locked: PostgreSQL need not re-evaluate a DELETE's old WHERE
    // after an unchanged tuple wait. The implementation must check time in a new statement.
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), finish)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(authentication_count(&pool).await, 0);
    assert!(
        f.enrollment
            .store
            .authenticate(f.enrollment.realm, session.verifier())
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn different_challenges_cannot_commit_updates_from_the_same_old_snapshot(pool: PgPool) {
    let mut f = SignIn::new(pool.clone()).await;
    let (a, response_a) = f.begin().await;
    let (b, response_b) = f.begin().await;
    let proof_a = f.proof(a, &response_a).await;
    let proof_b = f.proof(b, &response_b).await;
    let session_a = Secret::generate().unwrap();
    let session_b = Secret::generate().unwrap();
    let store = &f.enrollment.store;
    let request_a = f.request(a);
    let request_b = f.request(b);
    let (a, b) = tokio::join!(
        store.commit_authentication(&request_a, proof_a, session_a.verifier()),
        store.commit_authentication(&request_b, proof_b, session_b.verifier())
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(authentication_count(&pool).await, 1);
    let valid_a = store
        .authenticate(f.enrollment.realm, session_a.verifier())
        .await
        .is_ok();
    let valid_b = store
        .authenticate(f.enrollment.realm, session_b.verifier())
        .await
        .is_ok();
    assert_ne!(valid_a, valid_b);
}
