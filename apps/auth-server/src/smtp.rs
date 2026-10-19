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
    async fn passkey_recovery_completed(&self, email: &str) -> auth_core::Result<()> {
        self.send(email, "Passkey recovery completed", "A saved-code recovery request completed after the waiting period and proof of a replacement passkey. Previous passkeys and sessions were invalidated. Sign in with the replacement key and configure a new saved recovery code. If this was not you, contact the service operator through a trusted channel. This notice contains no credential, code or sign-in link.".to_owned()).await
    }
    async fn passkey_recovery_started(&self, email: &str) -> auth_core::Result<()> {
        self.send(email, "Passkey recovery was requested", "A saved recovery code was used to request passkey recovery. Existing keys remain usable during the waiting period. If this was not you, cancel through the service using an existing key or your saved recovery code. Never send that code by email. This notice contains no recovery code, browser capability or sign-in link.".to_owned()).await
    }
    async fn passkey_recovery_cancelled(&self, email: &str) -> auth_core::Result<()> {
        self.send(email, "Passkey recovery was cancelled", "A passkey recovery request was cancelled. Its saved code remains invalid and cannot start another request. Existing keys remain usable; sign in with a working key to configure a replacement saved code. This notice contains no credential or sign-in link.".to_owned()).await
    }
    async fn passkey_recovery_changed(&self, email: &str) -> auth_core::Result<()> {
        self.send(email, "Your passkey recovery configuration changed", "A saved recovery code was configured or replaced after a fresh passkey sign-in. The code is never sent by email. If this was not you, sign in with an existing key and replace the recovery configuration through the service. This notice contains no code, credential or sign-in link.".to_owned()).await
    }
    async fn passkeys_changed(&self, email: &str) -> auth_core::Result<()> {
        self.send(email, "Your passkeys changed", "A passkey on your authentication account was renamed or removed after a fresh passkey sign-in. Removal invalidates existing sessions. If this was not you, sign in with a remaining key and contact the service operator through a trusted channel. This notice contains no credential, recovery code or sign-in link.".to_owned()).await
    }
    async fn email_attachment(&self, email: &str, token: &Secret) -> auth_core::Result<()> {
        self.send(email, "Confirm contact email", format!(
            "A contact email was requested for your passkey account. Confirm only if you requested it, in the same browser while your passkey sign-in is still fresh. This link expires within five minutes and works once. It does not enable email sign-in or mailbox-only recovery.\n\n{}/email-attach#token={}\n\nIf you did not request this, ignore the message. No account has been merged or moved.",
            self.origin, token.expose())).await
    }
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
