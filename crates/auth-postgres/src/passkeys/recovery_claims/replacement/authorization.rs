use super::super::ownership;
use crate::{deadlines::Deadline, unavailable};
use auth_core::{Error, PasskeyRecoveryReplacementRequest, Result};
use sqlx::{Postgres, Transaction};

/// Owner -> claim -> private candidate. New clock statements follow all waits.
pub(super) async fn ready(
    tx: &mut Transaction<'_, Postgres>,
    request: &PasskeyRecoveryReplacementRequest,
) -> Result<Deadline> {
    let c = &request.claim;
    ownership::owner(tx, c.realm, c.user_id).await?;
    let deadline = ownership::claim(
        tx,
        c.realm,
        c.user_id,
        &c.rp_id,
        request.claim_id,
        Some(c.browser),
    )
    .await?;
    let ready: bool = sqlx::query_scalar(
        r#"
        SELECT not_before IS NOT NULL
        AND not_before<=clock_timestamp()
        AND (NOT notification_required
        OR notified_at IS NOT NULL)
        FROM auth_passkey_recovery_claims
        WHERE realm_id=$1
        AND user_id=$2
        AND id=$3
        AND completed_at IS NULL
        "#,
    )
    .bind(c.realm)
    .bind(c.user_id)
    .bind(request.claim_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .unwrap_or(false);
    if !ready {
        return Err(Error::Unauthorized);
    }
    Ok(deadline)
}

pub(super) async fn pending(
    tx: &mut Transaction<'_, Postgres>,
    request: &PasskeyRecoveryReplacementRequest,
    deadline: Deadline,
) -> Result<Deadline> {
    let c = &request.claim;
    let locked: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM auth_passkey_recovery_replacements WHERE realm_id=$1 AND claim_id=$2 FOR UPDATE")
    .bind(c.realm)
    .bind(request.claim_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?;
    if locked != Some(request.transaction) {
        return Err(Error::Unauthorized);
    }
    let expiry: i64 = sqlx::query_scalar(
        r#"
        SELECT (extract(epoch FROM expires_at)*1000000)::bigint
        FROM auth_passkey_recovery_replacements
        WHERE realm_id=$1
        AND claim_id=$2
        AND id=$3
        AND user_id=$4
        AND expires_at>clock_timestamp()
        "#,
    )
    .bind(c.realm)
    .bind(request.claim_id)
    .bind(request.transaction)
    .bind(c.user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    Ok(deadline.with_proof(expiry))
}

/// Mailbox proof consumers lock email before owner. Completion removes those
/// proofs, so select the email lock from a snapshot and revalidate after locking.
pub(super) async fn ready_for_commit(
    tx: &mut Transaction<'_, Postgres>,
    request: &PasskeyRecoveryReplacementRequest,
) -> Result<Deadline> {
    let c = &request.claim;
    let (email,): (Option<String>,) =
        sqlx::query_as("SELECT email FROM auth_users WHERE realm_id=$1 AND id=$2")
            .bind(c.realm)
            .bind(c.user_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?
            .ok_or(Error::Unauthorized)?;
    if let Some(email) = &email {
        crate::locking::lock_email(tx, c.realm, email).await?;
    }
    let deadline = ready(tx, request).await?;
    let same: bool = sqlx::query_scalar(
        "SELECT email IS NOT DISTINCT FROM $3::text FROM auth_users WHERE realm_id=$1 AND id=$2",
    )
    .bind(c.realm)
    .bind(c.user_id)
    .bind(&email)
    .fetch_one(&mut **tx)
    .await
    .map_err(unavailable)?;
    if !same {
        return Err(Error::Unauthorized);
    }
    Ok(deadline)
}
