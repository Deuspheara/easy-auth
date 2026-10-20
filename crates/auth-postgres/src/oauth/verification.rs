use super::{configuration, ownership};
use crate::unavailable;
use auth_core::{Error, OAuthExchange, Result};
use sqlx::PgPool;

pub(super) async fn check(pool: &PgPool, exchange: &OAuthExchange) -> Result<i64> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    configuration::lock(&mut tx, exchange.configuration()).await?;
    let owner = ownership::lock(&mut tx, exchange.configuration(), exchange.purpose()).await?;
    let cap = owner
        .deadline
        .as_ref()
        .map_or(exchange.expires_us(), |deadline| {
            deadline.expires_us().min(exchange.expires_us())
        });
    // One materialized wall-clock observation after every potential lock wait.
    // No row/table wait or network operation follows before this read commits.
    let now: i64 = sqlx::query_scalar(
        "WITH now AS MATERIALIZED (SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint AS us) SELECT us FROM now WHERE us < $1",
    ).bind(cap).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(now)
}
