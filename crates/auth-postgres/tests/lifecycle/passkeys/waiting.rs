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
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%SELECT u.id,coalesce(u.email,u.display_name) FROM auth_users u%FOR UPDATE OF u%')")
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

#[sqlx::test(migrations = "./migrations")]
async fn final_audit_wait_cannot_extend_enrollment_or_original_session_deadlines(pool: PgPool) {
    for stronger in [false, true] {
        for expire_pending in [true, false] {
            let f = Fixture::new(pool.clone()).await;
            let (id, response) = f.begin().await;
            let request = f.request(id);
            let state = f.store.load_enrollment(&request).await.unwrap();
            let encoded = state.encode_for_database().unwrap();
            let credential = f.service.verify_registration(&response, state).unwrap();
            if stronger {
                // Storage-policy fixture only: this test's signed proof is a new
                // registration, not native authentication provenance evidence.
                sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1")
                    .bind(f.realm).execute(&pool).await.unwrap();
                sqlx::query(
                    "UPDATE auth_sessions SET authentication_method='passkey' WHERE realm_id=$1",
                )
                .bind(f.realm)
                .execute(&pool)
                .await
                .unwrap();
            }
            let deadline_query = if expire_pending {
                sqlx::query("UPDATE auth_passkey_enrollments SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1")
                    .bind(id).execute(&pool).await.unwrap();
                "SELECT expires_at<=clock_timestamp() FROM auth_passkey_enrollments WHERE realm_id=$1"
            } else {
                sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 55 seconds' WHERE realm_id=$1")
                    .bind(f.realm).execute(&pool).await.unwrap();
                "SELECT authenticated_at<=clock_timestamp()-interval '5 minutes' FROM auth_sessions WHERE realm_id=$1"
            };
            let mut gate = pool.begin().await.unwrap();
            sqlx::query("SELECT pg_advisory_xact_lock(5320)")
                .execute(&mut *gate)
                .await
                .unwrap();
            sqlx::raw_sql("CREATE FUNCTION gate_enrollment_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='passkey_enrolled' THEN PERFORM pg_advisory_xact_lock(5320); END IF; RETURN NEW; END $$; CREATE TRIGGER gate_enrollment_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION gate_enrollment_audit();")
                .execute(&pool).await.unwrap();
            let store = f.store.clone();
            let finish = tokio::spawn(async move {
                store
                    .commit_enrollment(&request, &encoded, credential)
                    .await
            });
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%INSERT INTO auth_audit%')")
                        .fetch_one(&pool).await.unwrap();
                    if waiting { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.unwrap();
            assert!(
                !sqlx::query_scalar::<_, bool>(deadline_query)
                    .bind(f.realm)
                    .fetch_one(&pool)
                    .await
                    .unwrap(),
                "audit reached before deadline"
            );
            tokio::time::timeout(Duration::from_secs(8), async {
                while !sqlx::query_scalar::<_, bool>(deadline_query)
                    .bind(f.realm)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            gate.commit().await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), finish)
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(result, Err(Error::Unauthorized)),
                "post-audit expiry/freshness must roll back enrollment"
            );
            let keys: i64 =
                sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE realm_id=$1")
                    .bind(f.realm)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            let facts: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_enrolled'",
            )
            .bind(f.realm)
            .fetch_one(&pool)
            .await
            .unwrap();
            let pending: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM auth_passkey_enrollments WHERE realm_id=$1 AND id=$2",
            )
            .bind(f.realm)
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                (keys, facts, pending),
                (0, 0, 1),
                "key/audit/consumption roll back together"
            );
            sqlx::raw_sql("DROP TRIGGER gate_enrollment_audit ON auth_audit; DROP FUNCTION gate_enrollment_audit();")
                .execute(&pool).await.unwrap();
        }
    }
}
