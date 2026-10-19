use crate::{deadlines::Deadline, unavailable};
use auth_core::{Error, PasskeyRecoveryClaimInfo, Result, Verifier};
use sqlx::{Row, Transaction};
use uuid::Uuid;

pub(super) async fn owner(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    user: Uuid,
) -> Result<()> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(realm)
    .bind(user)
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    Ok(())
}

/// Owner is already locked. Only fresh-key or exact reserved-code cancellation
/// may omit a browser verifier after independently proving that authority.
pub(super) async fn claim(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    user: Uuid,
    rp: &str,
    id: Uuid,
    browser: Option<Verifier>,
) -> Result<Deadline> {
    let expiry: i64 = sqlx::query_scalar(r#"
        SELECT (extract(epoch FROM c.expires_at)*1000000)::bigint
        FROM auth_passkey_recovery_claims c
        JOIN auth_passkey_recovery_codes k ON k.realm_id=c.realm_id AND k.user_id=c.user_id AND k.rp_id=c.rp_id
        WHERE c.realm_id=$1 AND c.user_id=$2 AND c.rp_id=$3 AND c.id=$4
          AND ($5::bytea IS NULL OR c.browser_hash=$5) AND c.cancelled_at IS NULL
          AND c.code_version=k.version AND k.consumed_at IS NOT NULL
          AND c.expires_at>clock_timestamp() FOR UPDATE OF c
    "#).bind(realm).bind(user).bind(rp).bind(id).bind(browser.as_ref().map(|value|value.as_slice()))
        .fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
    Ok(Deadline::proof(expiry))
}

pub(super) async fn info(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    user: Uuid,
    rp: &str,
    id: Uuid,
) -> Result<PasskeyRecoveryClaimInfo> {
    // New statement after all row waits. Metadata is not a completion capability.
    let row = sqlx::query(r#"
        SELECT c.id,floor(extract(epoch FROM c.expires_at)*1000)::bigint AS expires,
            floor(extract(epoch FROM c.not_before)*1000)::bigint AS not_before,
            c.notification_required,coalesce(c.not_before<=clock_timestamp(),false) AS ready
        FROM auth_passkey_recovery_claims c
        JOIN auth_passkey_recovery_codes k ON k.realm_id=c.realm_id AND k.user_id=c.user_id AND k.rp_id=c.rp_id
        WHERE c.realm_id=$1 AND c.user_id=$2 AND c.rp_id=$3 AND c.id=$4
          AND c.cancelled_at IS NULL AND c.expires_at>clock_timestamp()
          AND c.code_version=k.version AND k.consumed_at IS NOT NULL
    "#).bind(realm).bind(user).bind(rp).bind(id)
        .fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
    Ok(PasskeyRecoveryClaimInfo {
        id: row.get("id"),
        expires_at_ms: row.get("expires"),
        not_before_ms: row.get("not_before"),
        notification_required: row.get("notification_required"),
        ready: row.get("ready"),
    })
}
