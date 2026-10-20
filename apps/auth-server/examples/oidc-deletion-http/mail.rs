use async_trait::async_trait;
use auth_core::{EmailDelivery, Error, Result, Secret};
use std::sync::atomic::{AtomicUsize, Ordering};

/// This email-free fixture must never request mail. A call is a visible failure,
/// not a fabricated mailbox, success receipt or alternate authentication path.
#[derive(Default)]
pub(super) struct NoDelivery(pub AtomicUsize);
impl NoDelivery {
    fn reject(&self) -> Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::Unavailable)
    }
}
#[async_trait]
impl EmailDelivery for NoDelivery {
    async fn passkey_recovery_completed(&self, _: &str) -> Result<()> {
        self.reject()
    }
    async fn passkey_recovery_started(&self, _: &str) -> Result<()> {
        self.reject()
    }
    async fn passkey_recovery_cancelled(&self, _: &str) -> Result<()> {
        self.reject()
    }
    async fn passkey_recovery_changed(&self, _: &str) -> Result<()> {
        self.reject()
    }
    async fn passkeys_changed(&self, _: &str) -> Result<()> {
        self.reject()
    }
    async fn email_attachment(&self, _: &str, _: &Secret) -> Result<()> {
        self.reject()
    }
    async fn sign_in(&self, _: &str, _: &Secret) -> Result<()> {
        self.reject()
    }
    async fn password_reset(&self, _: &str, _: &Secret) -> Result<()> {
        self.reject()
    }
    async fn password_changed(&self, _: &str) -> Result<()> {
        self.reject()
    }
    async fn email_change(&self, _: &str, _: &Secret) -> Result<()> {
        self.reject()
    }
    async fn account_deletion(&self, _: &str, _: &Secret) -> Result<()> {
        self.reject()
    }
    async fn email_changed(&self, _: &str) -> Result<()> {
        self.reject()
    }
    async fn account_deleted(&self, _: &str) -> Result<()> {
        self.reject()
    }
}
