use super::policy::{admit, credential_limit, fresh_owner};
use crate::unavailable;
use auth_core::{
    Error, MAX_PASSKEYS_PER_ACCOUNT, PasskeyEnrollmentContext, PasskeyEnrollmentStart, Result,
    Verifier,
};
use sqlx::PgPool;
use uuid::Uuid;

const MAX_PENDING_ENROLLMENTS: i64 = 3;

pub(super) async fn context(
    pool: &PgPool,
    realm: Uuid,
    session: Verifier,
    rp_id: &str,
) -> Result<PasskeyEnrollmentContext> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let (user_id, _, account_name) = fresh_owner(&mut tx, realm, session).await?;
    credential_limit(&mut tx, realm, user_id, rp_id).await?;
    let excluded_credentials = sqlx::query_scalar(
        r#"
        SELECT credential_id FROM auth_passkeys
        WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3
        ORDER BY id LIMIT $4
        "#,
    )
    .bind(realm)
    .bind(user_id)
    .bind(rp_id)
    .bind(MAX_PASSKEYS_PER_ACCOUNT as i64)
    .fetch_all(&mut *tx)
    .await
    .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(PasskeyEnrollmentContext {
        user_id,
        account_name,
        excluded_credentials,
    })
}

pub(super) async fn save(pool: &PgPool, pending: PasskeyEnrollmentStart) -> Result<()> {
    let encoded = pending.state.encode_for_database()?;
    let request = pending.request;
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let (user, session, _) = fresh_owner(&mut tx, request.realm, request.session).await?;
    if user != pending.user_id {
        return Err(Error::Unauthorized);
    }
    credential_limit(&mut tx, request.realm, user, &pending.rp_id).await?;
    admit(&mut tx, request.realm, user, request.source, false).await?;
    sqlx::query(
        r#"
        DELETE FROM auth_passkey_enrollments
        WHERE realm_id=$1 AND user_id=$2 AND expires_at<=clock_timestamp()
        "#,
    )
    .bind(request.realm)
    .bind(user)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_passkey_enrollments WHERE realm_id=$1 AND user_id=$2",
    )
    .bind(request.realm)
    .bind(user)
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    if count >= MAX_PENDING_ENROLLMENTS {
        return Err(Error::RateLimited);
    }
    sqlx::query(
        r#"
        INSERT INTO auth_passkey_enrollments(
            realm_id,id,user_id,session_id,browser_hash,rp_id,label,private_state
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(request.realm)
    .bind(request.transaction)
    .bind(user)
    .bind(session)
    .bind(request.browser.as_slice())
    .bind(pending.rp_id)
    .bind(pending.label)
    .bind(encoded)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)
}
