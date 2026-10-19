use crate::{Postgres, unavailable};
use auth_core::{Error, PasskeyRecoveryClaimRequest, Result};
use sqlx::Transaction;

const ATTEMPTS_PER_SOURCE: i32 = 40;
const ATTEMPTS_PER_ACCOUNT: i32 = 10;
const ATTEMPTS_PER_BROWSER: i32 = 10;

pub(super) enum Budget {
    Code,
    Browser,
}
const WINDOW_SECONDS: i32 = 10 * 60;

pub(super) async fn admit(
    store: &Postgres,
    request: &PasskeyRecoveryClaimRequest,
    budget: Budget,
) -> Result<()> {
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    if !spend(
        &mut tx,
        request.realm,
        "passkey_recovery_source",
        &request.source,
        ATTEMPTS_PER_SOURCE,
    )
    .await?
    {
        return Err(Error::RateLimited);
    }
    let (dimension, key, limit) = match budget {
        Budget::Code => (
            "passkey_recovery_user",
            request.user_id.as_bytes().to_vec(),
            ATTEMPTS_PER_ACCOUNT,
        ),
        Budget::Browser => {
            // Owner/RP scope prevents a reused browser capability from sharing
            // another account's continuation budget or erasure boundary.
            let mut key = request.user_id.as_bytes().to_vec();
            key.extend_from_slice(&request.browser);
            key.extend_from_slice(request.rp_id.as_bytes());
            ("passkey_recovery_browser", key, ATTEMPTS_PER_BROWSER)
        }
    };
    let admitted = spend(&mut tx, request.realm, dimension, &key, limit).await?;
    // Keep the source charge even when an account budget is exhausted. Neither
    // bucket looks up account presence or verifies a code before admission.
    tx.commit().await.map_err(unavailable)?;
    if !admitted {
        return Err(Error::RateLimited);
    }
    Ok(())
}

async fn spend(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    realm: uuid::Uuid,
    dimension: &str,
    key: &[u8],
    limit: i32,
) -> Result<bool> {
    let admitted: Option<i32> = sqlx::query_scalar(
        r#"
        INSERT INTO auth_rate_buckets(realm_id,dimension,key_hash,window_id,attempts)
        VALUES ($1,$2,sha256($3),floor(extract(epoch FROM clock_timestamp())/$5::integer)::bigint,1)
        ON CONFLICT (realm_id,dimension,key_hash,window_id) DO UPDATE
        SET attempts=auth_rate_buckets.attempts+1 WHERE auth_rate_buckets.attempts<$4
        RETURNING attempts
    "#,
    )
    .bind(realm)
    .bind(dimension)
    .bind(key)
    .bind(limit)
    .bind(WINDOW_SECONDS)
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?;
    Ok(admitted.is_some())
}

/// Code cancellation grants no access. Only source admission precedes the proof
/// lookup: an account/code bucket could be pre-exhausted to suppress an alerted
/// owner's cancellation. A correct proof immediately denies the current claim.
pub(super) async fn admit_source(
    store: &Postgres,
    realm: uuid::Uuid,
    source: auth_core::Verifier,
) -> Result<()> {
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    let allowed = spend(
        &mut tx,
        realm,
        "passkey_recovery_source",
        &source,
        ATTEMPTS_PER_SOURCE,
    )
    .await?;
    tx.commit().await.map_err(unavailable)?;
    if !allowed {
        return Err(Error::RateLimited);
    }
    Ok(())
}
