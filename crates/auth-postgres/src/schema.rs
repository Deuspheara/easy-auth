//! Schema administration stays in the PostgreSQL adapter, separate from auth policy.
use crate::Postgres;
use auth_core::{Error, Result};
use sqlx::{PgConnection, migrate::Migrate};
use std::time::Duration;

static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!();
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(5);
const VERIFICATION_STATEMENT_LIMIT: &str = "2000ms";
const ADMINISTRATION_LOCK_LIMIT: &str = "2000ms";

impl Postgres {
    pub async fn migrate(&self) -> Result<()> {
        let mut connection = self.pool.acquire().await.map_err(crate::unavailable)?;
        // SQLx's session migration lock must not survive a failed/cancelled run
        // in a pooled connection. Keep its permit until close completes.
        connection.close_on_drop();
        // Closing a client socket alone does not promptly interrupt a backend
        // already waiting on an advisory lock. Bound the server's wait as well;
        // do not impose the verification statement limit on migration execution.
        sqlx::query("SELECT set_config('lock_timeout', $1, false)")
            .bind(ADMINISTRATION_LOCK_LIMIT)
            .execute(&mut *connection)
            .await
            .map_err(crate::unavailable)?;
        MIGRATIONS
            .run_direct(&mut *connection)
            .await
            .map_err(|_| Error::Unavailable)
    }

    /// Verify the embedded current schema without creating history or applying DDL.
    /// Missing, dirty, unknown or checksum-mismatched migrations fail closed.
    pub async fn verify_schema(&self) -> Result<()> {
        tokio::time::timeout(VERIFICATION_TIMEOUT, async {
            let mut connection = self.pool.acquire().await.map_err(crate::unavailable)?;
            connection.close_on_drop();
            verify_connection(&mut connection).await
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
}

async fn verify_connection(connection: &mut PgConnection) -> Result<()> {
    sqlx::query(
        "SELECT set_config('statement_timeout', $1, false), set_config('lock_timeout', $1, false)",
    )
    .bind(VERIFICATION_STATEMENT_LIMIT)
    .execute(&mut *connection)
    .await
    .map_err(crate::unavailable)?;
    connection.lock().await.map_err(|_| Error::Unavailable)?;
    let checked = current_history(connection).await;
    let unlocked = connection.unlock().await.map_err(|_| Error::Unavailable);
    checked?;
    unlocked
}

async fn current_history(connection: &mut PgConnection) -> Result<()> {
    if connection
        .dirty_version()
        .await
        .map_err(|_| Error::Unavailable)?
        .is_some()
    {
        return Err(Error::Unavailable);
    }
    let applied = connection
        .list_applied_migrations()
        .await
        .map_err(|_| Error::Unavailable)?;
    let expected: Vec<_> = MIGRATIONS
        .iter()
        .filter(|m| !m.migration_type.is_down_migration())
        .collect();
    if applied.len() != expected.len()
        || applied.iter().zip(expected).any(|(actual, expected)| {
            actual.version != expected.version || actual.checksum != expected.checksum
        })
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}
