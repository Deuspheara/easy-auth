use super::keeping;
use crate::support::realm;
use auth_core::{RetentionCategory, RetentionRepository};
use easy_auth_postgres::Postgres;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

const ACTOR: &str = "easy-auth-owned-retention-check";

async fn waiting(pool: &PgPool) -> i32 {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND wait_event_type='Lock'")
                .bind(ACTOR).fetch_optional(pool).await.unwrap();
            if let Some(pid) = pid { return pid; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("maintenance must actually reach the table-lock wait")
}

async fn gone(pool: &PgPool, pid: i32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid=$1)")
                .bind(pid).fetch_one(pool).await.unwrap();
            if !exists { return; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("canceled maintenance must close its backend rather than return it to the pool")
}

#[sqlx::test(migrations = "./migrations")]
async fn cancellation_closes_an_observed_waiting_backend_without_later_deletion(pool: PgPool) {
    let (_, a) = realm(pool.clone()).await;
    sqlx::query("INSERT INTO auth_email_challenges(realm_id,token_hash,browser_hash,email,expires_at) VALUES($1,decode(repeat('01',32),'hex'),decode(repeat('02',32),'hex'),'owned-cancel@example.test',statement_timestamp()-interval '1 second')")
        .bind(a).execute(&pool).await.unwrap();
    let actor = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            pool.connect_options()
                .as_ref()
                .clone()
                .application_name(ACTOR),
        )
        .await
        .unwrap();
    let store = Postgres::new(actor.clone());
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_email_challenges IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        store
            .retain_batch(a, RetentionCategory::EmailChallenges, keeping())
            .await
    });
    let pid = waiting(&pool).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    gone(&pool, pid).await;
    gate.commit().await.unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_email_challenges WHERE realm_id=$1")
            .bind(a)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 1);
    assert_eq!(
        Postgres::new(actor.clone())
            .retain_batch(a, RetentionCategory::EmailChallenges, keeping())
            .await
            .unwrap()
            .deleted,
        1
    );
    actor.close().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn maintenance_selects_its_required_isolation_even_when_pool_defaults_differ(pool: PgPool) {
    let (_, a) = realm(pool.clone()).await;
    sqlx::query("INSERT INTO auth_email_challenges(realm_id,token_hash,browser_hash,email,expires_at) VALUES($1,decode(repeat('01',32),'hex'),decode(repeat('02',32),'hex'),'owned-isolation@example.test',statement_timestamp()-interval '1 second')")
        .bind(a).execute(&pool).await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION owned_retention_isolation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'owned isolation mismatch'; END IF; RETURN OLD; END $$; CREATE TRIGGER owned_retention_isolation BEFORE DELETE ON auth_email_challenges FOR EACH ROW EXECUTE FUNCTION owned_retention_isolation()")
        .execute(&pool).await.unwrap();
    let actor = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query(
                    "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ",
                )
                .execute(connection)
                .await?;
                Ok(())
            })
        })
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    let actual: String = sqlx::query_scalar("SHOW default_transaction_isolation")
        .fetch_one(&actor)
        .await
        .unwrap();
    assert_eq!(actual, "repeatable read");
    let result = Postgres::new(actor.clone())
        .retain_batch(a, RetentionCategory::EmailChallenges, keeping())
        .await;
    assert_eq!(
        result.unwrap().deleted,
        1,
        "the cleanup transaction must explicitly select fresh statement snapshots"
    );
    actor.close().await;
}
