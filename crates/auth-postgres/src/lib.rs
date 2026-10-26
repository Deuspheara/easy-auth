//! PostgreSQL transactions for the shared core. SQL row shapes are private.
mod account;
mod audit;
mod deadlines;
mod email;
mod identity;
#[cfg(feature = "issuer-clients")]
mod issuer;
mod locking;
mod notifications;
#[cfg(feature = "oauth-transactions")]
mod oauth;
#[cfg(feature = "passkeys")]
mod passkeys;
mod passwords;
mod recovery;
mod repository;
#[cfg(feature = "saml-requests")]
mod saml;
mod schema;
mod sessions;

use auth_core::{Error, Result};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct Postgres {
    pool: PgPool,
    #[cfg(feature = "apple-grants")]
    apple_grant_vault: Option<std::sync::Arc<auth_core::AppleGrantVault>>,
}
fn unavailable(_: sqlx::Error) -> Error {
    Error::Unavailable
}
impl Postgres {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "apple-grants")]
            apple_grant_vault: None,
        }
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
