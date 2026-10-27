use crate::Postgres;
use auth_core::AppleGrantVault;
use std::sync::Arc;
impl Postgres {
    /// Trusted explicit key composition. This does not select a provider flow,
    /// restore missing keys or make stored credentials into identity proofs.
    pub fn with_apple_grant_vault(mut self, vault: Arc<AppleGrantVault>) -> Self {
        self.apple_grant_vault = Some(vault);
        self
    }
}
