use super::Auth;
use crate::{Error, Result, SecurityNoticeKind};

impl Auth {
    /// Deliver at most one leased non-secret notice. SMTP errors leave durable retry work.
    /// Call repeatedly from a bounded worker in both embedded and standalone compositions.
    pub async fn deliver_security_notice(&self) -> Result<bool> {
        let Some(notice) = self.repository.claim_security_notice(self.realm).await? else {
            return Ok(false);
        };
        let delivery = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            match notice.kind {
                SecurityNoticeKind::PasskeysChanged => {
                    self.email.passkeys_changed(&notice.recipient).await
                }
                SecurityNoticeKind::PasswordReset => {
                    self.email.password_changed(&notice.recipient).await
                }
                SecurityNoticeKind::EmailChanged => {
                    self.email.email_changed(&notice.recipient).await
                }
                SecurityNoticeKind::AccountDeleted => {
                    self.email.account_deleted(&notice.recipient).await
                }
            }
        })
        .await
        .unwrap_or(Err(Error::Unavailable));
        self.repository
            .complete_security_notice(self.realm, notice.id, notice.lease, delivery.is_ok())
            .await?;
        delivery.map(|_| true)
    }
}
