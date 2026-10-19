use super::{linking::signed_in_owner, setup::Fixture};
use auth_core::{Error, OAuthPurpose, OAuthTransactionRepository};
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;

enum Gate {
    InsertRow,
    InsertStatement,
    DeleteRow,
}

async fn gate(pool: &PgPool, stage: Gate) -> Transaction<'static, Postgres> {
    let mut gate = pool
        .begin()
        .await
        .expect("test infrastructure: gate transaction");
    sqlx::query("SELECT pg_advisory_xact_lock(2201)")
        .execute(&mut *gate)
        .await
        .unwrap();
    let (operation, granularity) = match stage {
        Gate::InsertRow => ("INSERT", "ROW"),
        Gate::InsertStatement => ("INSERT", "STATEMENT"),
        Gate::DeleteRow => ("DELETE", "ROW"),
    };
    sqlx::raw_sql(&format!("CREATE FUNCTION oauth_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(2201); IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW; END $$; CREATE TRIGGER oauth_gate BEFORE {operation} ON auth_oauth_transactions FOR EACH {granularity} EXECUTE FUNCTION oauth_gate();"))
        .execute(pool).await.unwrap();
    gate
}

async fn expire_while_waiting(pool: &PgPool, pattern: &str, link: bool) {
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: independent observer");
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)")
                .bind(pattern).fetch_one(&observer).await.expect("test infrastructure: observe expected lock");
            if waiting {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: operation never reached expected lock");
    let query = if link {
        "SELECT expires_at<=clock_timestamp() FROM auth_sessions"
    } else {
        "SELECT expires_at<=clock_timestamp() FROM auth_oauth_transactions"
    };
    assert!(
        !sqlx::query_scalar::<_, bool>(query)
            .fetch_one(&observer)
            .await
            .unwrap(),
        "test infrastructure: expected lock must precede expiry"
    );
    tokio::time::timeout(Duration::from_secs(8), async {
        while !sqlx::query_scalar::<_, bool>(query)
            .fetch_one(&observer)
            .await
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("test infrastructure: database clock did not cross deadline");
    observer.close().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn callback_expiring_during_final_delete_rolls_back_consumption(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let start = f.start().await;
    sqlx::query(
        "UPDATE auth_oauth_transactions SET expires_at=clock_timestamp()+interval '5 seconds'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let gate = gate(&pool, Gate::DeleteRow).await;
    let request = f.request(&start, OAuthPurpose::SignIn);
    let release = async {
        expire_while_waiting(
            &pool,
            "DELETE FROM auth_oauth_transactions WHERE realm_id=$1 AND state_hash%",
            false,
        )
        .await;
        gate.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(f.store.consume_oauth(&request), release);
    assert!(
        matches!(result, Err(Error::Unauthorized)),
        "infrastructure failure is not expiry rejection"
    );
    assert_eq!(f.pending().await, 1, "expired delete must roll back");
}

#[sqlx::test(migrations = "./migrations")]
async fn unchanged_pending_row_wait_cannot_extend_original_expiry(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let start = f.start().await;
    sqlx::query(
        "UPDATE auth_oauth_transactions SET expires_at=clock_timestamp()+interval '5 seconds'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT state_hash FROM auth_oauth_transactions FOR UPDATE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let request = f.request(&start, OAuthPurpose::SignIn);
    let release = async {
        expire_while_waiting(
            &pool,
            "%SELECT (extract(epoch FROM expires_at)%FOR UPDATE%",
            false,
        )
        .await;
        gate.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(f.store.consume_oauth(&request), release);
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.pending().await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn link_session_expiring_during_start_insert_cannot_publish_state(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (user, session) = signed_in_owner(&f).await;
    sqlx::query("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '5 seconds'")
        .execute(&pool)
        .await
        .unwrap();
    let gate = gate(&pool, Gate::InsertRow).await;
    let release = async {
        expire_while_waiting(&pool, "%INSERT INTO auth_oauth_transactions%", true).await;
        gate.commit().await.unwrap();
    };
    let intent = f.intent(OAuthPurpose::Link {
        user,
        session: session.verifier(),
    });
    let (result, ()) = tokio::join!(f.flow.begin(&intent), release);
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.pending().await, 0, "expired preparation must roll back");
}

#[sqlx::test(migrations = "./migrations")]
async fn link_expiring_before_insert_clock_is_auth_rejection_not_database_failure(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (user, session) = signed_in_owner(&f).await;
    sqlx::query("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '5 seconds'")
        .execute(&pool)
        .await
        .unwrap();
    let gate = gate(&pool, Gate::InsertStatement).await;
    let release = async {
        expire_while_waiting(&pool, "%INSERT INTO auth_oauth_transactions%", true).await;
        gate.commit().await.unwrap();
    };
    let intent = f.intent(OAuthPurpose::Link {
        user,
        session: session.verifier(),
    });
    let (result, ()) = tokio::join!(f.flow.begin(&intent), release);
    assert!(
        matches!(result, Err(Error::Unauthorized)),
        "late session expiry must not become Unavailable"
    );
    assert_eq!(f.pending().await, 0);
}
