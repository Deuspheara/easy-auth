//! PostgreSQL transactions for the shared core. SQL row shapes are private.
mod account;
mod email;
mod locking;
mod notifications;
mod passwords;
mod recovery;
mod repository;
mod sessions;

use auth_core::{Error, Result};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct Postgres {
    pool: PgPool,
}
fn unavailable(_: sqlx::Error) -> Error {
    Error::Unavailable
}
impl Postgres {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!()
            .run(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }
    /// Only trusted startup configuration provisions realms, never request input.
    pub async fn ensure_realm(&self, realm: Uuid) -> Result<()> {
        sqlx::query("INSERT INTO auth_realms(id) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(realm)
            .execute(&self.pool)
            .await
            .map_err(unavailable)?;
        Ok(())
    }
}
