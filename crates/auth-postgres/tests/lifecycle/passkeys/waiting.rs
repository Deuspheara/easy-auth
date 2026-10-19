use super::*;
use auth_core::{Error, PasskeyRepository, Repository};
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn revalidates_freshness_and_challenge_expiry_after_waiting_for_owner(pool: PgPool) {
    for expire_challenge in [true, false] {
        let f = Fixture::new(pool.clone()).await;
        let (id, response) = f.begin().await;
        let request = f.request(id);
        let state = f.store.load_enrollment(&request).await.unwrap();
        let encoded = state.encode_for_database().unwrap();
        let credential = f.service.verify_registration(&response, state).unwrap();
        let user = f
            .store
            .authenticate(f.realm, f.session.verifier())
            .await
            .unwrap();
        let mut gate = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
            .bind(f.realm)
            .bind(user.id)
            .execute(&mut *gate)
            .await
            .unwrap();
        let store = f.store.clone();
        let finish = tokio::spawn(async move {
            store
                .commit_enrollment(&request, &encoded, credential)
                .await
        });
        // Observe a real PostgreSQL lock wait before changing expiry; no guessed sleep.
        tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%SELECT u.id,u.email FROM auth_users u%FOR UPDATE OF u%')")
                    .fetch_one(&pool).await.unwrap();
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        if expire_challenge {
            sqlx::query("UPDATE auth_passkey_enrollments SET expires_at=clock_timestamp()-interval '1 second' WHERE realm_id=$1 AND id=$2")
                .bind(f.realm).bind(id).execute(&mut *gate).await.unwrap();
        } else {
            sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE realm_id=$1 AND token_hash=$2")
                .bind(f.realm).bind(f.session.verifier().as_slice()).execute(&mut *gate).await.unwrap();
        }
        gate.commit().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), finish)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(Error::Unauthorized)));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE realm_id=$1")
            .bind(f.realm)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
