use async_trait::async_trait;
use auth_core::{EmailDelivery, Error, Result, Secret};

/// The fixture seeds verified sessions through repository proofs; it has no mail
/// bypass endpoint or success-returning delivery stub. All actual mail is disabled.
pub(super) struct DisabledMail;
#[async_trait]
impl EmailDelivery for DisabledMail {
    async fn sign_in(&self, _: &str, _: &Secret) -> Result<()> {
        Err(Error::Unavailable)
    }
    async fn password_reset(&self, _: &str, _: &Secret) -> Result<()> {
        Err(Error::Unavailable)
    }
    async fn password_changed(&self, _: &str) -> Result<()> {
        Err(Error::Unavailable)
    }
    async fn email_change(&self, _: &str, _: &Secret) -> Result<()> {
        Err(Error::Unavailable)
    }
    async fn account_deletion(&self, _: &str, _: &Secret) -> Result<()> {
        Err(Error::Unavailable)
    }
    async fn email_changed(&self, _: &str) -> Result<()> {
        Err(Error::Unavailable)
    }
    async fn account_deleted(&self, _: &str) -> Result<()> {
        Err(Error::Unavailable)
    }
}
