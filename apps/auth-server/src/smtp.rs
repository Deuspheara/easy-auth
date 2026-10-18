use async_trait::async_trait;
use auth_core::{EmailDelivery, Error, Secret};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::time::Duration;

pub(crate) struct Smtp {
    pub(crate) transport: AsyncSmtpTransport<Tokio1Executor>,
    pub(crate) from: lettre::message::Mailbox,
    pub(crate) origin: String,
}
impl Smtp {
    async fn send(&self, email: &str, subject: &str, body: String) -> auth_core::Result<()> {
        let message = Message::builder()
            .from(self.from.clone())
            .to(email.parse().map_err(|_| Error::InvalidInput)?)
            .subject(subject)
            .body(body)
            .map_err(|_| Error::Unavailable)?;
        tokio::time::timeout(Duration::from_secs(10), self.transport.send(message))
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }
}
#[async_trait]
impl EmailDelivery for Smtp {
    async fn email_change(&self, email: &str, token: &Secret) -> auth_core::Result<()> {
        self.send(email,"Confirm email change",format!("An email change was requested for your authentication account. Confirm the separate links sent to both the current and proposed addresses in the requesting browser. Complete them promptly after signing in; each link expires within five minutes.\n\n{}/email-change#token={}\n\nIf you did not request this, do not confirm it and secure your account.",self.origin,token.expose())).await
    }
    async fn account_deletion(&self, email: &str, token: &Secret) -> auth_core::Result<()> {
        self.send(email,"Confirm account deletion",format!("Deletion of your authentication account was requested. This removes its authentication credentials and sessions; consuming applications manage their own data. Only continue if you requested deletion. The link works only in the requesting browser within the fresh sign-in window.\n\n{}/account-delete#token={}\n\nIf you did not request this, ignore this message and secure your account.",self.origin,token.expose())).await
    }
    async fn email_changed(&self, email: &str) -> auth_core::Result<()> {
        self.send(email,"Your sign-in email changed","Your authentication account's email was changed after confirmation of both addresses. Existing sessions and pending proofs were invalidated. If this was not you, secure your mailbox and contact the service operator through a trusted channel.".to_owned()).await
    }
    async fn account_deleted(&self, email: &str) -> auth_core::Result<()> {
        self.send(email,"Your authentication account was deleted","Your authentication account, credentials and sessions were deleted. Consuming applications manage their own data. If this was not you, secure your mailbox and contact the service operator through a trusted channel. This notice contains no credential or sign-in link.".to_owned()).await
    }
    async fn password_reset(&self, email: &str, token: &Secret) -> auth_core::Result<()> {
        self.send(email,"Password reset request",format!("A password reset was requested. If this mailbox has a password credential, open this link in the browser that requested it. The link expires in ten minutes and works once.\n\n{}/reset#token={}\n\nIf you did not request this, ignore this email. No account changes have been made.",self.origin,token.expose())).await
    }
    async fn password_changed(&self, email: &str) -> auth_core::Result<()> {
        self.send(email,"Your password was reset",format!("Your password was reset. Existing sessions and outstanding sign-in/recovery links were invalidated. Sign in again at {}/ using the new password.\n\nIf you did not make this change, your mailbox or account may be compromised. Secure your mailbox and contact the service operator through a trusted channel. This message contains no sign-in link or password.",self.origin)).await
    }
    async fn sign_in(&self, email: &str, token: &Secret) -> auth_core::Result<()> {
        let to = email.parse().map_err(|_| Error::InvalidInput)?;
        let message = Message::builder().from(self.from.clone()).to(to).subject("Your sign-in link")
            .body(format!("Open in the browser that requested sign-in. This link expires in ten minutes and works once.\n\n{}/#token={}\n\nIf you did not request this, ignore this email.", self.origin, token.expose()))
            .map_err(|_| Error::Unavailable)?;
        tokio::time::timeout(Duration::from_secs(10), self.transport.send(message))
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }
}
