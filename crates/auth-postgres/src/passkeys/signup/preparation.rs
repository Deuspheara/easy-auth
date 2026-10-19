use super::admission::admit;
use crate::unavailable;
use auth_core::{
    Error, PasskeySignupRegistrationContext, PasskeySignupRequest, PasskeySignupStart,
    PrivatePasskeyRegistration, Result, VerifiedPasskeySignupRegistration,
};
use sqlx::PgPool;
use uuid::Uuid;

const MAX_PENDING_PER_BROWSER: i64 = 3;
const MAX_PENDING_PER_REALM: i64 = 256;

pub(super) async fn save(pool: &PgPool, pending: PasskeySignupStart) -> Result<()> {
    let request = &pending.request;
    admit(pool, request, false).await?;
    if pending.prospective_user.is_nil() || request.transaction.is_nil() || request.realm.is_nil() {
        return Err(Error::InvalidInput);
    }
    let state = pending.state.encode_for_database()?;
    let mut tx = pool.begin().await.map_err(unavailable)?;
    // One bounded pending namespace per realm; no user exists to lock yet.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':passkey_signup_pending',0))")
        .bind(request.realm).execute(&mut *tx).await.map_err(unavailable)?;
    sqlx::query(
        "DELETE FROM auth_passkey_signups WHERE realm_id=$1 AND expires_at<=clock_timestamp()",
    )
    .bind(request.realm)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    let (total, browser): (i64, i64) = sqlx::query_as(
        r#"
        SELECT count(*),count(*) FILTER (WHERE browser_hash=$2)
        FROM auth_passkey_signups WHERE realm_id=$1
        "#,
    )
    .bind(request.realm)
    .bind(request.browser.as_slice())
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    if total >= MAX_PENDING_PER_REALM || browser >= MAX_PENDING_PER_BROWSER {
        return Err(Error::RateLimited);
    }
    sqlx::query(
        r#"
        INSERT INTO auth_passkey_signups(
            realm_id,id,prospective_user,browser_hash,rp_id,display_name,stage,registration_state)
        VALUES ($1,$2,$3,$4,$5,$6,'registration',$7)
        "#,
    )
    .bind(request.realm)
    .bind(request.transaction)
    .bind(pending.prospective_user)
    .bind(request.browser.as_slice())
    .bind(&pending.rp_id)
    .bind(&pending.display_name)
    .bind(state)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)
}

pub(super) async fn load(
    pool: &PgPool,
    request: &PasskeySignupRequest,
    rp_id: &str,
) -> Result<PasskeySignupRegistrationContext> {
    admit(pool, request, true).await?;
    let (prospective_user, state): (Uuid, Vec<u8>) = sqlx::query_as(
        r#"
        SELECT prospective_user,registration_state FROM auth_passkey_signups
        WHERE realm_id=$1 AND id=$2 AND browser_hash=$3 AND rp_id=$4
          AND stage='registration' AND expires_at>clock_timestamp()
        "#,
    )
    .bind(request.realm)
    .bind(request.transaction)
    .bind(request.browser.as_slice())
    .bind(rp_id)
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    Ok(PasskeySignupRegistrationContext {
        prospective_user,
        state: PrivatePasskeyRegistration::decode_from_database(&state)?,
    })
}

pub(super) async fn advance(
    pool: &PgPool,
    request: &PasskeySignupRequest,
    registration: VerifiedPasskeySignupRegistration,
) -> Result<()> {
    if registration.realm() != request.realm {
        return Err(Error::Unauthorized);
    }
    let mut tx = pool.begin().await.map_err(unavailable)?;
    // Separate lock and clock statement: even an unchanged-row wait must not
    // authorize an expired registration or extend the original signup lifetime.
    let locked: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM auth_passkey_signups WHERE realm_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(request.realm)
    .bind(request.transaction)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    locked.ok_or(Error::Unauthorized)?;
    let advanced: Option<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE auth_passkey_signups SET stage='assertion',registration_state=NULL,
          authentication_state=$7,candidate_id=$8,candidate=$9
        WHERE realm_id=$1 AND id=$2 AND browser_hash=$3 AND rp_id=$4
          AND prospective_user=$5 AND registration_state=$6 AND stage='registration'
          AND expires_at>clock_timestamp()
        RETURNING id
        "#,
    )
    .bind(request.realm)
    .bind(request.transaction)
    .bind(request.browser.as_slice())
    .bind(registration.rp_id())
    .bind(registration.prospective_user())
    .bind(registration.expected_registration_for_database())
    .bind(registration.assertion_for_database()?)
    .bind(registration.credential_id())
    .bind(registration.credential_for_database()?)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    advanced.ok_or(Error::Unauthorized)?;
    tx.commit().await.map_err(unavailable)
}
