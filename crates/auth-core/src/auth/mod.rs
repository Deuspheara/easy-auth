mod account;
mod admission;
mod email;
mod notifications;
mod passwords;
mod recovery;
mod sessions;

use crate::{EmailDelivery, PasswordService, Repository, Result};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct Auth {
    realm: Uuid,
    repository: Arc<dyn Repository>,
    email: Arc<dyn EmailDelivery>,
    passwords: Option<Arc<PasswordService>>,
}
impl Auth {
    /// Trusted composition identity; request input never selects the realm.
    pub fn realm(&self) -> Uuid {
        self.realm
    }
    pub fn new(
        realm: Uuid,
        repository: Arc<dyn Repository>,
        email: Arc<dyn EmailDelivery>,
    ) -> Self {
        Self {
            realm,
            repository,
            email,
            passwords: None,
        }
    }
    /// Enable passwords with an explicitly supplied compromised-password policy.
    pub fn with_passwords(mut self, passwords: Arc<PasswordService>) -> Self {
        self.passwords = Some(passwords);
        self
    }
    pub async fn ready(&self) -> Result<()> {
        self.repository.ready().await
    }
}
