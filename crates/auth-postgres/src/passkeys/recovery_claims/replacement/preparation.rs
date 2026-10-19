use super::authorization;
use crate::unavailable;
use auth_core::{
    Error, PasskeyRecoveryReplacementRequest, PasskeyRecoveryReplacementStart,
    PrivatePasskeyRegistration, Result, VerifiedPasskeyRecoveryRegistration,
};
use sqlx::PgPool;

const CEREMONY_SECONDS: i32 = 120;

pub(super) async fn save(pool: &PgPool, pending: PasskeyRecoveryReplacementStart) -> Result<()> {
    let request = &pending.request;
    let c = &request.claim;
    let state = pending.state.encode_for_database()?;
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let deadline = authorization::ready(&mut tx, request).await?;
    sqlx::query("DELETE FROM auth_passkey_recovery_replacements WHERE realm_id=$1 AND claim_id=$2")
        .bind(c.realm)
        .bind(request.claim_id)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    let expiry: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO auth_passkey_recovery_replacements(realm_id,claim_id,id,user_id,registration_state,expires_at)
        VALUES ($1,$2,$3,$4,$5,clock_timestamp()+make_interval(secs=>$6))
        RETURNING (extract(epoch FROM expires_at)*1000000)::bigint
        "#,
    )
    .bind(c.realm)
    .bind(request.claim_id)
    .bind(request.transaction)
    .bind(c.user_id)
    .bind(state)
    .bind(CEREMONY_SECONDS)
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    deadline.with_proof(expiry).check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)
}

pub(super) async fn load(
    pool: &PgPool,
    request: &PasskeyRecoveryReplacementRequest,
) -> Result<PrivatePasskeyRegistration> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let deadline = authorization::ready(&mut tx, request).await?;
    let deadline = authorization::pending(&mut tx, request, deadline).await?;
    let state: Vec<u8> = sqlx::query_scalar(
        r#"
        SELECT registration_state
        FROM auth_passkey_recovery_replacements
        WHERE realm_id=$1
        AND claim_id=$2
        AND id=$3
        AND stage='registration'
        "#,
    )
    .bind(request.claim.realm)
    .bind(request.claim_id)
    .bind(request.transaction)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    let state = PrivatePasskeyRegistration::decode_from_database(&state)?;
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(state)
}

pub(super) async fn advance(
    pool: &PgPool,
    request: &PasskeyRecoveryReplacementRequest,
    registration: VerifiedPasskeyRecoveryRegistration,
) -> Result<()> {
    let c = &request.claim;
    if registration.realm() != c.realm
        || registration.user_id() != c.user_id
        || registration.rp_id() != c.rp_id
    {
        return Err(Error::Unauthorized);
    }
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let deadline = authorization::ready(&mut tx, request).await?;
    let deadline = authorization::pending(&mut tx, request, deadline).await?;
    let changed: Option<uuid::Uuid> = sqlx::query_scalar(
        r#"
        UPDATE auth_passkey_recovery_replacements
        SET stage='assertion',registration_state=NULL,authentication_state=$4,candidate_id=$5,candidate=$6
        WHERE realm_id=$1
        AND claim_id=$2
        AND id=$3
        AND stage='registration'
        AND registration_state=$7
        RETURNING id
        "#,
    )
    .bind(c.realm)
    .bind(request.claim_id)
    .bind(request.transaction)
    .bind(registration.assertion_for_database()?)
    .bind(registration.credential_id())
    .bind(registration.credential_for_database()?)
    .bind(registration.expected_registration_for_database())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    changed.ok_or(Error::Unauthorized)?;
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)
}
