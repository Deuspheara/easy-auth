use crate::unavailable;
use auth_core::Result;
use sqlx::{Postgres, Transaction};

pub(super) async fn now(tx: &mut Transaction<'_, Postgres>) -> Result<i64> {
    sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
        .fetch_one(&mut **tx)
        .await
        .map_err(unavailable)
}
