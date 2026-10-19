use super::admission::admit;
use crate::unavailable;
use auth_core::{
    Error, MAX_PASSKEYS_PER_ACCOUNT, PasskeyAuthenticationRequest, PasskeyAuthenticationStart,
    Result, StoredPasskey,
};
use sqlx::PgPool;
use uuid::Uuid;

const MAX_PENDING_PER_BROWSER: i64 = 3;

pub(super) async fn prepare(
    pool: &PgPool,
    request: &PasskeyAuthenticationRequest,
    rp_id: &str,
    owner: Option<Uuid>,
) -> Result<Vec<StoredPasskey>> {
    admit(pool, request, false).await?;
    let Some(owner) = owner else {
        return Ok(Vec::new());
    };
    let rows: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT credential_id,credential FROM auth_passkeys
        WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 ORDER BY id LIMIT $4
    "#,
    )
    .bind(request.realm)
    .bind(owner)
    .bind(rp_id)
    .bind(MAX_PASSKEYS_PER_ACCOUNT as i64)
    .fetch_all(pool)
    .await
    .map_err(unavailable)?;
    if rows.is_empty() {
        return Err(Error::Unauthorized);
    }
    rows.into_iter()
        .map(|(id, encoded)| {
            StoredPasskey::decode_from_database(request.realm, owner, rp_id, &id, &encoded)
        })
        .collect()
}

pub(super) async fn save(pool: &PgPool, pending: PasskeyAuthenticationStart) -> Result<()> {
    let request = pending.request;
    if pending.state.realm() != request.realm {
        return Err(Error::InvalidInput);
    }
    let encoded = pending.state.encode_for_database()?;
    let mut tx = pool.begin().await.map_err(unavailable)?;
    // This lock owns browser pending-count admission only. Commit uses user -> key ->
    // ceremony locks and never acquires this advisory lock, avoiding reversed order.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':' || encode($2,'hex'),19))",
    )
    .bind(request.realm)
    .bind(request.browser.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    if let Some(owner) = pending.state.owner() {
        let user: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
                .bind(request.realm)
                .bind(owner)
                .fetch_optional(&mut *tx)
                .await
                .map_err(unavailable)?;
        user.ok_or(Error::Unauthorized)?;
    }
    sqlx::query("DELETE FROM auth_passkey_authentications WHERE realm_id=$1 AND browser_hash=$2 AND expires_at<=clock_timestamp()")
        .bind(request.realm).bind(request.browser.as_slice()).execute(&mut *tx).await.map_err(unavailable)?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_passkey_authentications WHERE realm_id=$1 AND browser_hash=$2",
    )
    .bind(request.realm)
    .bind(request.browser.as_slice())
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    if count >= MAX_PENDING_PER_BROWSER {
        return Err(Error::RateLimited);
    }
    sqlx::query(r#"
        INSERT INTO auth_passkey_authentications(realm_id,id,user_id,purpose,browser_hash,rp_id,private_state)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
    "#).bind(request.realm).bind(request.transaction).bind(pending.state.owner())
        .bind(pending.state.purpose()).bind(request.browser.as_slice()).bind(pending.rp_id).bind(encoded)
        .execute(&mut *tx).await.map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)
}
