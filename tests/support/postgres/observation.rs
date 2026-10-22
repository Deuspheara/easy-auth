use sqlx::PgPool;
use std::time::Duration;

#[path = "locks.rs"]
mod locks;
pub(crate) use locks::{locked, observer};

pub(crate) async fn audit(pool: &PgPool) {
    locked(pool, "%INSERT INTO auth_audit%").await;
}
pub(crate) async fn expired(pool: &PgPool, cap: i64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let expired: bool = sqlx::query_scalar(
                "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint >= $1",
            )
            .bind(cap)
            .fetch_one(pool)
            .await
            .expect("test infrastructure: observe original PostgreSQL proof deadline");
            if expired {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("test infrastructure: original PostgreSQL proof cap did not expire");
}
