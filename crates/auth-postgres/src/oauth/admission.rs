use crate::unavailable;
use auth_core::{Error, OAuthRequest, Result};
use sqlx::PgPool;

const START_BROWSER_LIMIT: i32 = 10;
const START_SOURCE_LIMIT: i32 = 40;
const CONSUME_BROWSER_LIMIT: i32 = 20;
const CONSUME_SOURCE_LIMIT: i32 = 80;

/// Failed lookup attempts spend committed budget, independently of later rollback.
pub(super) async fn admit(pool: &PgPool, request: &OAuthRequest, consume: bool) -> Result<()> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let dimensions = if consume {
        [
            ("consume_browser", request.browser, CONSUME_BROWSER_LIMIT),
            ("consume_source", request.source, CONSUME_SOURCE_LIMIT),
        ]
    } else {
        [
            ("start_browser", request.browser, START_BROWSER_LIMIT),
            ("start_source", request.source, START_SOURCE_LIMIT),
        ]
    };
    for (dimension, key, limit) in dimensions {
        let admitted: Option<i32> = sqlx::query_scalar(
            r#"
            INSERT INTO auth_oauth_admission(realm_id,dimension,key_hash,window_id,attempts)
            VALUES ($1,$2,sha256($3),floor(extract(epoch FROM clock_timestamp())/600)::bigint,1)
            ON CONFLICT (realm_id,dimension,key_hash,window_id) DO UPDATE
            SET attempts=auth_oauth_admission.attempts+1 WHERE auth_oauth_admission.attempts<$4 RETURNING attempts
            "#,
        ).bind(request.configuration.realm()).bind(dimension).bind(key.as_slice()).bind(limit)
            .fetch_optional(&mut *tx).await.map_err(unavailable)?;
        if admitted.is_none() {
            return Err(Error::RateLimited);
        }
    }
    tx.commit().await.map_err(unavailable)
}
