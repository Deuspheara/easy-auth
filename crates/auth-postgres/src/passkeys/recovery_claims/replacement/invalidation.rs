use crate::unavailable;
use auth_core::Result;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Caller holds owner lock. Invalidate all owner-bound ceremonies across RPs;
/// discoverable snapshots still recheck live credentials in ordinary completion.
pub(super) async fn revoke(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    user: Uuid,
    new_key: Uuid,
) -> Result<()> {
    sqlx::query("DELETE FROM auth_passkeys WHERE realm_id=$1 AND user_id=$2 AND id<>$3")
        .bind(realm)
        .bind(user)
        .bind(new_key)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND user_id=$2 AND revoked_at IS NULL")
        .bind(realm)
        .bind(user)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    for table in [
        "auth_passkey_enrollments",
        "auth_passkey_authentications",
        "auth_email_attachments",
        "auth_email_changes",
        "auth_account_deletions",
        "auth_passkey_recovery_setups",
    ] {
        // Static table names only; this transaction owns every mutation.
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE realm_id=$1 AND user_id=$2"
        ))
        .bind(realm)
        .bind(user)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    }
    // Completion already holds the revalidated email-before-owner lock, matching
    // mailbox proof consumers. No email lock may be acquired at this point.
    for table in ["auth_email_challenges", "auth_password_resets"] {
        sqlx::query(&format!(
            r#"
        DELETE
        FROM {table} p USING auth_users u
        WHERE u.realm_id=$1
        AND u.id=$2
        AND p.realm_id=u.realm_id
        AND p.email=u.email
        "#
        ))
        .bind(realm)
        .bind(user)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    }
    // Supersede other-RP saved proofs too: a stale recovery configuration must
    // not replace the newly proven key after this owner-wide recovery.
    sqlx::query(
        r#"
        DELETE
        FROM auth_passkey_recovery_codes
        WHERE realm_id=$1
        AND user_id=$2
        AND rp_id<>(SELECT rp_id
        FROM auth_passkeys
        WHERE realm_id=$1
        AND id=$3)
        "#,
    )
    .bind(realm)
    .bind(user)
    .bind(new_key)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    Ok(())
}
