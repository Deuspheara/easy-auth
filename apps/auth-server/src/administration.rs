//! One-shot schema command composition; no runtime listeners or workers.
use crate::configuration::database;
use auth_postgres::Postgres;

const ADMINISTRATION_CONNECTIONS: u32 = 1;

/// Apply embedded migrations using separately supplied administration credentials.
pub async fn migrate_database() -> Result<(), Box<dyn std::error::Error>> {
    let pool = database::pool(ADMINISTRATION_CONNECTIONS).await?;
    let result = Postgres::new(pool.clone()).migrate().await;
    pool.close().await;
    result.map_err(|_| "database migration failed".into())
}
