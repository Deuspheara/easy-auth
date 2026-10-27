//! Explicit one-shot trusted maintenance composition, shared with embedded callers.
mod configuration;

use crate::configuration::database;
use auth_core::{RetentionReport, run_retention};
use auth_postgres::Postgres;

pub async fn retain_database() -> Result<RetentionReport, Box<dyn std::error::Error>> {
    let (realm, policy) = configuration::read()?;
    let pool = database::pool(1).await?;
    let store = Postgres::new(pool.clone());
    let result = async {
        // Exact current schema is required. Never migrate, provision a realm or
        // select a fallback from a destructive maintenance command.
        store.verify_schema().await?;
        run_retention(&store, realm, policy).await
    }
    .await;
    pool.close().await;
    result.map_err(|_| "database retention failed; earlier batches may have committed".into())
}
