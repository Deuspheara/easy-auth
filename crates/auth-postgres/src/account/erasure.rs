//! Erasure after the caller has locked and authorized the exact account/session.
//! This helper confers no authority; the caller retains its final deadline check.
use crate::{audit, unavailable};
use auth_core::{AuditEvent, Result};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn erase(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    user: Uuid,
    email: Option<&str>,
) -> Result<()> {
    if let Some(email) = email {
        for table in ["auth_email_challenges", "auth_password_resets"] {
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE realm_id=$1 AND email=$2"
            ))
            .bind(realm)
            .bind(email)
            .execute(&mut **tx)
            .await
            .map_err(unavailable)?;
        }
        sqlx::query("DELETE FROM auth_rate_buckets WHERE realm_id=$1 AND dimension IN ('email','password_email') AND key_hash=sha256($2)")
        .bind(realm)
        .bind(email.as_bytes())
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    }
    sqlx::query(
        r#"
        DELETE FROM auth_rate_buckets
        WHERE realm_id=$1 AND dimension IN ('passkey_enroll_user','passkey_finish_user','sensitive_user','passkey_recovery_user')
          AND key_hash=sha256($2)
        "#,
    )
    .bind(realm)
    .bind(user.as_bytes().as_slice())
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    // Only current owned claim-capability buckets can be linked to this
    // subject; independent invalid-capability/source abuse metadata remains.
    sqlx::query(
        r#"
        DELETE FROM auth_rate_buckets b USING auth_passkey_recovery_claims c
        WHERE b.realm_id=$1 AND c.realm_id=$1 AND c.user_id=$2
          AND b.dimension='passkey_recovery_browser'
          AND b.key_hash=sha256(uuid_send(c.user_id)||c.browser_hash||convert_to(c.rp_id,'UTF8'))
    "#,
    )
    .bind(realm)
    .bind(user)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    audit::erase_subject(tx, realm, user).await?;
    sqlx::query("DELETE FROM auth_users WHERE realm_id=$1 AND id=$2")
        .bind(realm)
        .bind(user)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    audit::record(tx, realm, AuditEvent::AccountDeleted).await?;
    if let Some(email) = email {
        sqlx::query("INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind) VALUES ($1,$2,NULL,$3,'account_deleted')")
        .bind(realm)
        .bind(Uuid::new_v4())
        .bind(email)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    }
    Ok(())
}
