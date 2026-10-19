use super::ownership;
use crate::{audit, deadlines::Deadline, unavailable};
use auth_core::{
    AuditEvent, Error, PASSKEY_RECOVERY_DELAY_SECONDS, PASSKEY_RECOVERY_LIFETIME_SECONDS,
    PasskeyRecoveryClaimInfo, PasskeyRecoveryClaimRequest, Result, Verifier,
};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn begin(
    pool: &PgPool,
    request: &PasskeyRecoveryClaimRequest,
    id: Uuid,
    code: Verifier,
) -> Result<PasskeyRecoveryClaimInfo> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    ownership::owner(&mut tx, request.realm, request.user_id).await?;
    let (version, consumed): (Uuid, bool) = sqlx::query_as(
        r#"
        SELECT version,consumed_at IS NOT NULL FROM auth_passkey_recovery_codes
        WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND code_hash=$4 FOR UPDATE
    "#,
    )
    .bind(request.realm)
    .bind(request.user_id)
    .bind(&request.rp_id)
    .bind(code.as_slice())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    if consumed {
        let existing: Uuid = sqlx::query_scalar(
            r#"
            SELECT id FROM auth_passkey_recovery_claims
            WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND code_version=$4 AND browser_hash=$5
        "#,
        )
        .bind(request.realm)
        .bind(request.user_id)
        .bind(&request.rp_id)
        .bind(version)
        .bind(request.browser.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        let deadline = ownership::claim(
            &mut tx,
            request.realm,
            request.user_id,
            &request.rp_id,
            existing,
            Some(request.browser),
        )
        .await?;
        let info = ownership::info(
            &mut tx,
            request.realm,
            request.user_id,
            &request.rp_id,
            existing,
        )
        .await?;
        deadline.check(&mut tx).await?;
        tx.commit().await.map_err(unavailable)?;
        return Ok(info);
    }
    let recipient: Option<String> = sqlx::query_scalar("SELECT email FROM auth_users WHERE realm_id=$1 AND id=$2 AND email IS NOT NULL AND email_verified_at IS NOT NULL")
        .bind(request.realm).bind(request.user_id).fetch_optional(&mut *tx).await.map_err(unavailable)?;
    // One bounded claim per owner/RP. A new configured generation supersedes old
    // state; its queued start notices cascade, and late acknowledgements cannot revive it.
    sqlx::query(
        "DELETE FROM auth_passkey_recovery_claims WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3",
    )
    .bind(request.realm)
    .bind(request.user_id)
    .bind(&request.rp_id)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    let expiry: i64 = sqlx::query_scalar(r#"
        WITH instant AS (SELECT clock_timestamp() AS now)
        INSERT INTO auth_passkey_recovery_claims(realm_id,user_id,rp_id,id,code_version,browser_hash,
            created_at,expires_at,delay_seconds,notification_required,not_before)
        SELECT $1,$2,$3,$4,$5,$6,now,now+make_interval(secs=>$7::integer),$8,$9,
            CASE WHEN $9 THEN NULL ELSE now+make_interval(secs=>$8::integer) END FROM instant
        RETURNING (extract(epoch FROM expires_at)*1000000)::bigint
    "#).bind(request.realm).bind(request.user_id).bind(&request.rp_id).bind(id).bind(version).bind(request.browser.as_slice())
        .bind(PASSKEY_RECOVERY_LIFETIME_SECONDS).bind(PASSKEY_RECOVERY_DELAY_SECONDS).bind(recipient.is_some())
        .fetch_one(&mut *tx).await.map_err(unavailable)?;
    sqlx::query("UPDATE auth_passkey_recovery_codes SET consumed_at=clock_timestamp() WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND version=$4")
        .bind(request.realm).bind(request.user_id).bind(&request.rp_id).bind(version)
        .execute(&mut *tx).await.map_err(unavailable)?;
    audit::record(
        &mut tx,
        request.realm,
        AuditEvent::PasskeyRecoveryStarted {
            user_id: request.user_id,
            claim_id: id,
        },
    )
    .await?;
    if let Some(recipient) = recipient {
        sqlx::query("INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind,recovery_claim_id) VALUES ($1,$2,$3,$4,'passkey_recovery_started',$5)")
            .bind(request.realm).bind(Uuid::new_v4()).bind(request.user_id).bind(recipient).bind(id)
            .execute(&mut *tx).await.map_err(unavailable)?;
    }
    let info = ownership::info(&mut tx, request.realm, request.user_id, &request.rp_id, id).await?;
    Deadline::proof(expiry).check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(info)
}
