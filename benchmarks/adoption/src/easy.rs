use async_trait::async_trait;
use auth_core::{Auth, EmailDelivery, Password, PasswordService, Secret};
use auth_postgres::Postgres;
use easy_auth_adoption_probes::{PASSWORD, Probe, Result, SESSIONS, measure, pool};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Default)]
struct Mailbox(Mutex<Option<String>>);
#[async_trait]
impl EmailDelivery for Mailbox {
    async fn sign_in(&self, _: &str, token: &Secret) -> auth_core::Result<()> {
        *self.0.lock().unwrap() = Some(token.expose().to_owned());
        Ok(())
    }
    async fn password_reset(&self, _: &str, _: &Secret) -> auth_core::Result<()> {
        Err(auth_core::Error::Unavailable)
    }
    async fn password_changed(&self, _: &str) -> auth_core::Result<()> {
        Err(auth_core::Error::Unavailable)
    }
    async fn email_change(&self, _: &str, _: &Secret) -> auth_core::Result<()> {
        Err(auth_core::Error::Unavailable)
    }
    async fn account_deletion(&self, _: &str, _: &Secret) -> auth_core::Result<()> {
        Err(auth_core::Error::Unavailable)
    }
    async fn email_changed(&self, _: &str) -> auth_core::Result<()> {
        Err(auth_core::Error::Unavailable)
    }
    async fn account_deleted(&self, _: &str) -> auth_core::Result<()> {
        Err(auth_core::Error::Unavailable)
    }
}
struct Easy {
    auth: Auth,
    sessions: Vec<Secret>,
}
#[async_trait]
impl Probe for Easy {
    async fn validate(&self, session: usize) -> Result<bool> {
        match self.auth.authenticate(&self.sessions[session]).await {
            Ok(_) => Ok(true),
            Err(auth_core::Error::Unauthorized) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    async fn revoke(&self, session: usize) -> Result<()> {
        Ok(self.auth.logout(&self.sessions[session]).await?)
    }
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let store = Arc::new(Postgres::new(pool().await?));
    store.migrate().await?;
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await?;
    let mailbox = Arc::new(Mailbox::default());
    // Development fixture corpus only, never a production compromised-password policy.
    let passwords = Arc::new(PasswordService::new("blocked comparison fixture password")?);
    let auth = Auth::new(realm, store, mailbox.clone()).with_passwords(passwords);
    let mut sessions = Vec::new();
    for index in 0..SESSIONS {
        let browser = auth
            .start_email(&format!("user{index}@example.test"), "127.0.0.1")
            .await?;
        let proof = Secret::parse(
            mailbox
                .0
                .lock()
                .unwrap()
                .take()
                .ok_or("missing delivered proof")?,
        )?;
        let current = auth.finish_email(proof, browser).await?;
        sessions.push(
            auth.enroll_password(&current, Password::parse(PASSWORD.into())?, "127.0.0.1")
                .await?,
        );
    }
    measure("easy-auth", Arc::new(Easy { auth, sessions })).await
}
