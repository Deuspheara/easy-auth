use crate::unavailable;
use auth_core::{Error, PasskeySignupRequest, Result};
use sqlx::PgPool;

/// Failed protocol/lookup attempts spend budget in a separately committed transaction.
pub(super) async fn admit(
    pool: &PgPool,
    request: &PasskeySignupRequest,
    finish: bool,
) -> Result<()> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let (browser_dimension, source_dimension, browser_limit, source_limit) = if finish {
        (
            "passkey_signup_finish_browser",
            "passkey_signup_finish_source",
            20,
            40,
        )
    } else {
        (
            "passkey_signup_start_browser",
            "passkey_signup_start_source",
            10,
            20,
        )
    };
    for (dimension, key, limit) in [
        (browser_dimension, request.browser.as_slice(), browser_limit),
        (source_dimension, request.source.as_slice(), source_limit),
    ] {
        let admitted: Option<i32> = sqlx::query_scalar(
            r#"
            INSERT INTO auth_rate_buckets(realm_id,dimension,key_hash,window_id,attempts)
            VALUES ($1,$2,sha256($3),floor(extract(epoch FROM clock_timestamp())/600)::bigint,1)
            ON CONFLICT (realm_id,dimension,key_hash,window_id) DO UPDATE
            SET attempts=auth_rate_buckets.attempts+1 WHERE auth_rate_buckets.attempts<$4
            RETURNING attempts
            "#,
        )
        .bind(request.realm)
        .bind(dimension)
        .bind(key)
        .bind(limit)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?;
        if admitted.is_none() {
            return Err(Error::RateLimited);
        }
    }
    tx.commit().await.map_err(unavailable)
}
