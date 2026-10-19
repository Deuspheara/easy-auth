use super::{gates::*, *};
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn validation_and_inventory_roll_back_touch_when_original_deadline_expires(pool: PgPool) {
    for inventory in [false, true] {
        for idle in [false, true] {
            let f = Fixture::new(pool.clone()).await;
            let (update, deadline) = if idle {
                (
                    "UPDATE auth_sessions SET last_seen_at=clock_timestamp()-interval '29 minutes 55 seconds' WHERE realm_id=$1",
                    "SELECT last_seen_at<=clock_timestamp()-interval '30 minutes' FROM auth_sessions WHERE realm_id=$1",
                )
            } else {
                (
                    "UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1",
                    "SELECT expires_at<=clock_timestamp() FROM auth_sessions WHERE realm_id=$1",
                )
            };
            sqlx::query(update)
                .bind(f.realm)
                .execute(&pool)
                .await
                .unwrap();
            let before = f.snapshot().await;
            let gate = touch_gate(&pool).await;
            let store = f.store.clone();
            let current = f.session.verifier();
            let finish = tokio::spawn(async move {
                if inventory {
                    store
                        .list_sessions(f.realm, current, None)
                        .await
                        .map(|_| ())
                } else {
                    store.authenticate(f.realm, current).await.map(|_| ())
                }
            });
            wait_and_expire(
                &pool,
                "%UPDATE auth_sessions SET last_seen_at%",
                deadline,
                f.realm,
            )
            .await;
            gate.commit().await.unwrap();
            assert!(
                matches!(finished(finish).await, Err(Error::Unauthorized)),
                "touch must not extend the original authority across a write wait"
            );
            f.assert_unchanged(before).await;
            sqlx::query("DROP TRIGGER deadline_touch_gate ON auth_sessions")
                .execute(&pool)
                .await
                .unwrap();
        }
    }
}

async fn touch_gate(pool: &PgPool) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5401)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION deadline_touch_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(5401); RETURN NEW; END $$; CREATE TRIGGER deadline_touch_gate BEFORE UPDATE OF last_seen_at ON auth_sessions FOR EACH ROW EXECUTE FUNCTION deadline_touch_gate();")
        .execute(pool).await.unwrap();
    gate
}
