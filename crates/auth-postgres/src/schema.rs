//! Schema administration stays in the PostgreSQL adapter, separate from auth policy.
use crate::Postgres;
use auth_core::{Error, Result};

impl Postgres {
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!()
            .run(&self.pool)
            .await
            .map_err(|_| Error::Unavailable)
    }
}
