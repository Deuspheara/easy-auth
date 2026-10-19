use async_trait::async_trait;
use auth_core::{EmailDelivery, Secret};
use std::sync::Mutex;

#[derive(Default)]
pub(crate) struct Mail {
    pub(crate) attachments: Mutex<Vec<(String, String)>>,
    pub(crate) fail_attachments: Mutex<bool>,
    pub(crate) sign_ins: Mutex<Vec<String>>,
    pub(crate) resets: Mutex<Vec<String>>,
    pub(crate) notices: Mutex<usize>,
    pub(crate) fail_notices: Mutex<bool>,
    pub(crate) changes: Mutex<Vec<(String, String)>>,
    pub(crate) deletions: Mutex<Vec<String>>,
}
#[async_trait]
impl EmailDelivery for Mail {
    async fn email_attachment(&self, email: &str, token: &Secret) -> auth_core::Result<()> {
        if *self.fail_attachments.lock().unwrap() {
            return Err(auth_core::Error::Unavailable);
        }
        self.attachments
            .lock()
            .unwrap()
            .push((email.to_owned(), token.expose().to_owned()));
        Ok(())
    }
    async fn email_change(&self, email: &str, token: &Secret) -> auth_core::Result<()> {
        self.changes
            .lock()
            .unwrap()
            .push((email.to_owned(), token.expose().to_owned()));
        Ok(())
    }
    async fn account_deletion(&self, _email: &str, token: &Secret) -> auth_core::Result<()> {
        self.deletions
            .lock()
            .unwrap()
            .push(token.expose().to_owned());
        Ok(())
    }
    async fn email_changed(&self, _email: &str) -> auth_core::Result<()> {
        *self.notices.lock().unwrap() += 1;
        Ok(())
    }
    async fn account_deleted(&self, _email: &str) -> auth_core::Result<()> {
        *self.notices.lock().unwrap() += 1;
        Ok(())
    }
    async fn password_reset(&self, _email: &str, token: &Secret) -> auth_core::Result<()> {
        self.resets.lock().unwrap().push(token.expose().to_owned());
        Ok(())
    }
    async fn password_changed(&self, _email: &str) -> auth_core::Result<()> {
        if *self.fail_notices.lock().unwrap() {
            return Err(auth_core::Error::Unavailable);
        }
        *self.notices.lock().unwrap() += 1;
        Ok(())
    }

    async fn sign_in(&self, _email: &str, token: &Secret) -> auth_core::Result<()> {
        self.sign_ins
            .lock()
            .unwrap()
            .push(token.expose().to_owned());
        Ok(())
    }
}
