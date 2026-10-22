use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

pub(crate) async fn observer(pool: &PgPool) -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: independent PostgreSQL lock/clock observer")
}
pub(crate) async fn locked(pool: &PgPool, pattern: &str) {
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)").bind(pattern)
                .fetch_one(pool).await.expect("test infrastructure: observe actual PostgreSQL lock wait");
            if waiting {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: PostgreSQL operation did not reach the expected lock wait");
}
