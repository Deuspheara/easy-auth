use crate::{audit, unavailable};
use auth_core::{AuditEvent, Error, PasskeyRecoverySetupRequest, Result, Verifier};
use sqlx::{PgPool, Transaction};
use uuid::Uuid;

async fn caller(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    request: &PasskeyRecoverySetupRequest,
) -> Result<super::super::authority::Caller> {
    let caller =
        super::super::authority::fresh_passkey_caller(tx, request.realm, request.session).await?;
    let proven: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM auth_passkeys
            WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND last_used_at IS NOT NULL
        )
        "#,
    )
    .bind(request.realm)
    .bind(caller.user)
    .bind(&request.rp_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(unavailable)?;
    if !proven {
        return Err(Error::Unauthorized);
    }
    Ok(caller)
}

pub(super) async fn prepare(
    pool: &PgPool,
    request: &PasskeyRecoverySetupRequest,
    id: Uuid,
    code: Verifier,
) -> Result<()> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let caller = caller(&mut tx, request).await?;
    sqlx::query(
        r#"
        INSERT INTO auth_passkey_recovery_setups(realm_id,user_id,rp_id,id,session_id,code_hash)
        VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (realm_id,user_id,rp_id) DO UPDATE
        SET id=EXCLUDED.id,session_id=EXCLUDED.session_id,
            code_hash=EXCLUDED.code_hash,expires_at=EXCLUDED.expires_at
        "#,
    )
    .bind(request.realm)
    .bind(caller.user)
    .bind(&request.rp_id)
    .bind(id)
    .bind(caller.session)
    .bind(code.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    caller.deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)
}

pub(super) async fn confirm(
    pool: &PgPool,
    request: &PasskeyRecoverySetupRequest,
    id: Uuid,
    code: Verifier,
) -> Result<()> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let caller = caller(&mut tx, request).await?;
    let expires: i64 = sqlx::query_scalar(
        r#"
        SELECT (extract(epoch FROM expires_at)*1000000)::bigint
        FROM auth_passkey_recovery_setups
        WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND id=$4
          AND session_id=$5 AND code_hash=$6 AND expires_at>clock_timestamp()
        FOR UPDATE
        "#,
    )
    .bind(request.realm)
    .bind(caller.user)
    .bind(&request.rp_id)
    .bind(id)
    .bind(caller.session)
    .bind(code.as_slice())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    let deadline = caller.deadline.with_proof(expires);
    sqlx::query(
        r#"
        INSERT INTO auth_passkey_recovery_codes(realm_id,user_id,rp_id,version,code_hash)
        VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (realm_id,user_id,rp_id) DO UPDATE
        SET version=EXCLUDED.version,code_hash=EXCLUDED.code_hash,confirmed_at=EXCLUDED.confirmed_at
        "#,
    )
    .bind(request.realm)
    .bind(caller.user)
    .bind(&request.rp_id)
    .bind(id)
    .bind(code.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    sqlx::query("DELETE FROM auth_passkey_recovery_setups WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND id=$4")
        .bind(request.realm).bind(caller.user).bind(&request.rp_id).bind(id)
        .execute(&mut *tx).await.map_err(unavailable)?;
    audit::record(
        &mut tx,
        request.realm,
        AuditEvent::PasskeyRecoveryConfigured {
            user_id: caller.user,
            actor_session_id: caller.session,
        },
    )
    .await?;
    sqlx::query(
        r#"
        INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind)
        SELECT realm_id,$3,id,email,'passkey_recovery_changed' FROM auth_users
        WHERE realm_id=$1 AND id=$2 AND email IS NOT NULL AND email_verified_at IS NOT NULL
        "#,
    )
    .bind(request.realm)
    .bind(caller.user)
    .bind(Uuid::new_v4())
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)
}
