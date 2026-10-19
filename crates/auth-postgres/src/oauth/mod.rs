mod admission;
mod configuration;
mod ownership;
mod transactions;

use crate::Postgres;
use async_trait::async_trait;
use auth_core::{OAuthRequest, OAuthTransactionRepository, Result};

#[async_trait]
impl OAuthTransactionRepository for Postgres {
    async fn save_oauth(&self, request: &OAuthRequest) -> Result<i64> {
        transactions::save(&self.pool, request).await
    }
    async fn consume_oauth(&self, request: &OAuthRequest) -> Result<i64> {
        transactions::take(&self.pool, request).await
    }
    async fn cancel_oauth(&self, request: &OAuthRequest) -> Result<()> {
        transactions::take(&self.pool, request).await.map(|_| ())
    }
}
