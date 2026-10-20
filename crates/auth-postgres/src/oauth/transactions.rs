use super::{admission, configuration, ownership};
use crate::{deadlines::Deadline, unavailable};
use auth_core::{Error, OAuthRequest, Result};
use sqlx::PgPool;

const MAX_PENDING_PER_BROWSER: i64 = 3;
const MAX_PENDING_PER_REALM: i64 = 256;

pub(super) async fn save(pool: &PgPool, request: &OAuthRequest, redirect: &str) -> Result<i64> {
    if !request.configuration.permits_return(redirect) {
        return Err(Error::InvalidInput);
    }
    admission::admit(pool, request, false).await?;
    let realm = request.configuration.realm();
    let mut tx = pool.begin().await.map_err(unavailable)?;
    // Serialize the entire pending namespace, including different connections.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':oauth_pending',0))",
    )
    .bind(realm)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    configuration::lock(&mut tx, &request.configuration).await?;
    let owner = ownership::lock(&mut tx, &request.configuration, &request.purpose).await?;
    sqlx::query(
        "DELETE FROM auth_oauth_transactions WHERE realm_id=$1 AND expires_at<=clock_timestamp()",
    )
    .bind(realm)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    let (total, browser): (i64, i64) = sqlx::query_as(
        "SELECT count(*),count(*) FILTER (WHERE browser_hash=$2) FROM auth_oauth_transactions WHERE realm_id=$1",
    ).bind(realm).bind(request.browser.as_slice()).fetch_one(&mut *tx).await.map_err(unavailable)?;
    if total >= MAX_PENDING_PER_REALM || browser >= MAX_PENDING_PER_BROWSER {
        return Err(Error::RateLimited);
    }
    let expires: i64 = sqlx::query_scalar(
        r#"
        WITH clock AS (SELECT clock_timestamp() AS now), deadline AS (
          SELECT now,least(now+interval '5 minutes',coalesce(
            to_timestamp(floor($12::numeric/1000000))+mod($12::numeric,1000000)*interval '1 microsecond',
            now+interval '5 minutes')) AS expires FROM clock
        )
        INSERT INTO auth_oauth_transactions(realm_id,connection_id,client_id,revision,
            state_hash,browser_hash,nonce_hash,pkce_hash,purpose,user_id,session_id,created_at,expires_at,redirect_uri)
        SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now,expires,$13
        FROM deadline WHERE expires>now
        RETURNING (extract(epoch FROM expires_at)*1000000)::bigint
        "#,
    ).bind(realm).bind(request.configuration.connection()).bind(request.configuration.client())
        .bind(request.configuration.revision()).bind(request.state.as_slice()).bind(request.browser.as_slice())
        .bind(request.nonce.as_slice()).bind(request.pkce.as_slice())
        .bind(owner.purpose).bind(owner.user).bind(owner.session)
        .bind(owner.deadline.as_ref().map(Deadline::expires_us)).bind(redirect).fetch_optional(&mut *tx).await.map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
    let deadline = owner
        .deadline
        .map_or_else(|| Deadline::proof(expires), |cap| cap.with_proof(expires));
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(expires)
}

pub(super) async fn take(pool: &PgPool, request: &OAuthRequest, redirect: &str) -> Result<i64> {
    if !request.configuration.permits_return(redirect) {
        return Err(Error::InvalidInput);
    }
    admission::admit(pool, request, true).await?;
    let realm = request.configuration.realm();
    let mut tx = pool.begin().await.map_err(unavailable)?;
    // Disable/reconfiguration serializes before owner/session and pending locks.
    configuration::lock(&mut tx, &request.configuration).await?;
    let owner = ownership::lock(&mut tx, &request.configuration, &request.purpose).await?;
    let expires: i64 = sqlx::query_scalar(
        r#"
        SELECT (extract(epoch FROM expires_at)*1000000)::bigint FROM auth_oauth_transactions
        WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND revision=$4
          AND state_hash=$5 AND browser_hash=$6 AND nonce_hash=$7 AND pkce_hash=$8
          AND purpose=$9 AND user_id IS NOT DISTINCT FROM $10::uuid
          AND session_id IS NOT DISTINCT FROM $11::uuid AND redirect_uri=$12 AND expires_at>clock_timestamp() FOR UPDATE
        "#,
    )
    .bind(realm)
    .bind(request.configuration.connection())
    .bind(request.configuration.client())
    .bind(request.configuration.revision())
    .bind(request.state.as_slice())
    .bind(request.browser.as_slice())
    .bind(request.nonce.as_slice())
    .bind(request.pkce.as_slice())
    .bind(owner.purpose)
    .bind(owner.user)
    .bind(owner.session)
    .bind(redirect)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    sqlx::query("DELETE FROM auth_oauth_transactions WHERE realm_id=$1 AND state_hash=$2")
        .bind(realm)
        .bind(request.state.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    let deadline = owner
        .deadline
        .map_or_else(|| Deadline::proof(expires), |cap| cap.with_proof(expires));
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(expires)
}
