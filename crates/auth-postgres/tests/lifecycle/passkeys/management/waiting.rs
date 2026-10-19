use super::*;
use auth_core::Error;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn management_rejects_original_freshness_expiring_during_final_audit_or_notice(pool: PgPool) {
    for remove in [false, true] {
        for notice in [false, true] {
            let f = Management::new(pool.clone(), false).await;
            let (id, mut token) = f.add_key("Spare").await;
            f.sign_in(&mut token).await;
            let key = f.key(id).await;
            sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 55 seconds' WHERE token_hash=$1")
                .bind(f.session.verifier().as_slice()).execute(&pool).await.unwrap();
            let before = f.snapshot().await;
            let table = if notice {
                "auth_security_notifications"
            } else {
                "auth_audit"
            };
            let mut gate = pool.begin().await.unwrap();
            sqlx::query("SELECT pg_advisory_xact_lock(200020)")
                .execute(&mut *gate)
                .await
                .unwrap();
            sqlx::raw_sql(&format!("CREATE OR REPLACE FUNCTION management_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind IN ('passkey_renamed','passkey_removed','passkeys_changed') THEN PERFORM pg_advisory_xact_lock(200020); END IF; RETURN NEW; END $$; CREATE TRIGGER management_gate BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION management_gate();"))
                .execute(&pool).await.unwrap();
            let store = f.fixture.store.clone();
            let service = f.fixture.service.clone();
            let realm = f.fixture.realm;
            let session = Secret::parse(f.session.expose().to_owned()).unwrap();
            let action = tokio::spawn(async move {
                let flow = PasskeyManagement::new(realm, service, store);
                if remove {
                    flow.remove(&session, SOURCE, key.id, key.version).await
                } else {
                    flow.rename(&session, SOURCE, key.id, key.version, "Late")
                        .await
                        .map(|_| ())
                }
            });
            let observer = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_with(pool.connect_options().as_ref().clone())
                .await
                .expect("test infrastructure: observer connection");
            tokio::time::timeout(Duration::from_secs(5),async {
                loop {
                    let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=200020 AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT granted)")
                        .fetch_one(&observer).await.unwrap();
                    if waiting { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.expect("test infrastructure: action must reach the final-write gate");
            let query = "SELECT authenticated_at<=clock_timestamp()-interval '5 minutes' FROM auth_sessions WHERE token_hash=$1";
            assert!(
                !sqlx::query_scalar::<_, bool>(query)
                    .bind(f.session.verifier().as_slice())
                    .fetch_one(&observer)
                    .await
                    .unwrap(),
                "test infrastructure: lock must be reached before deadline"
            );
            tokio::time::timeout(Duration::from_secs(8), async {
                while !sqlx::query_scalar::<_, bool>(query)
                    .bind(f.session.verifier().as_slice())
                    .fetch_one(&observer)
                    .await
                    .unwrap()
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("test infrastructure: database deadline crossing");
            gate.commit().await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), action)
                .await
                .expect("test infrastructure: completion timeout")
                .unwrap();
            assert!(
                matches!(result, Err(Error::Unauthorized)),
                "expired authority must roll back; infrastructure errors are not acceptance"
            );
            f.assert_unchanged(before).await;
            observer.close().await;
            sqlx::query(&format!("DROP TRIGGER management_gate ON {table}"))
                .execute(&pool)
                .await
                .unwrap();
        }
    }
}
