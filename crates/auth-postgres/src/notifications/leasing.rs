use crate::{Postgres, unavailable};
use auth_core::Result;
use uuid::Uuid;

use auth_core::{Error, SecurityNotice, SecurityNoticeKind};
use sqlx::Row;

impl Postgres {
    pub(crate) async fn claim_security_notice(
        &self,
        realm: Uuid,
    ) -> Result<Option<SecurityNotice>> {
        let lease = Uuid::new_v4();
        let row = sqlx::query(
            r#"
            WITH due AS (SELECT id
            FROM auth_security_notifications
            WHERE realm_id=$1
            AND attempts<8
            AND next_attempt_at<=clock_timestamp()
            AND (lease_until IS NULL
            OR lease_until<=clock_timestamp())
            ORDER BY next_attempt_at,id
            FOR
            UPDATE SKIP LOCKED
            LIMIT 1)
            UPDATE auth_security_notifications n
            SET attempts=n.attempts+1,lease_id=$2,lease_until=clock_timestamp()+interval '30 seconds'
            FROM due
            WHERE n.realm_id=$1
            AND n.id=due.id
            RETURNING n.id,n.recipient,n.kind
            "#,
        )
        .bind(realm)
        .bind(lease)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        row.map(|row| {
            let kind = match row.get::<String, _>("kind").as_str() {
                "providers_changed" => SecurityNoticeKind::ProvidersChanged,
                "passkey_recovery_completed" => SecurityNoticeKind::PasskeyRecoveryCompleted,
                "passkey_recovery_started" => SecurityNoticeKind::PasskeyRecoveryStarted,
                "passkey_recovery_cancelled" => SecurityNoticeKind::PasskeyRecoveryCancelled,
                "passkey_recovery_changed" => SecurityNoticeKind::PasskeyRecoveryChanged,
                "passkeys_changed" => SecurityNoticeKind::PasskeysChanged,
                "password_reset" => SecurityNoticeKind::PasswordReset,
                "email_changed" => SecurityNoticeKind::EmailChanged,
                "account_deleted" => SecurityNoticeKind::AccountDeleted,
                _ => return Err(Error::Unavailable),
            };
            Ok(SecurityNotice {
                id: row.get("id"),
                lease,
                recipient: row.get("recipient"),
                kind,
            })
        })
        .transpose()
    }
}
