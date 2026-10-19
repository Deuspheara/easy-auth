use crate::unavailable;
use auth_core::{Error, PasskeyAuthenticationRequest, Result};
use sqlx::PgPool;

const ATTEMPTS_PER_BROWSER: i32 = 20;
const ATTEMPTS_PER_SOURCE: i32 = 40;

/// Separate committed admission, including for malformed/absent ceremony attempts.
pub(super) async fn admit(
    pool: &PgPool,
    request: &PasskeyAuthenticationRequest,
    finish: bool,
) -> Result<()> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let (browser_dimension, source_dimension) = if finish {
        ("passkey_auth_finish_browser", "passkey_auth_finish_source")
    } else {
        ("passkey_auth_start_browser", "passkey_auth_start_source")
    };
    for (dimension, key, limit) in [
        (
            browser_dimension,
            request.browser.as_slice(),
            ATTEMPTS_PER_BROWSER,
        ),
        (
            source_dimension,
            request.source.as_slice(),
            ATTEMPTS_PER_SOURCE,
        ),
    ] {
        let admitted: Option<i32> = sqlx::query_scalar(
            r#"
            INSERT INTO auth_rate_buckets(realm_id,dimension,key_hash,window_id,attempts)
            VALUES ($1,$2,sha256($3),floor(extract(epoch FROM clock_timestamp())/600)::bigint,1)
            ON CONFLICT (realm_id,dimension,key_hash,window_id) DO UPDATE
            SET attempts=auth_rate_buckets.attempts+1
            WHERE auth_rate_buckets.attempts<$4 RETURNING attempts
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
