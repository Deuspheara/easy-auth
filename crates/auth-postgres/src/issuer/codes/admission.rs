use crate::{Postgres, unavailable};
use auth_core::{
    Error, ISSUER_TOKEN_ATTEMPTS_PER_MINUTE, ISSUER_TOKEN_RATE_WINDOW_SECONDS, IssuerAuthority,
    MAX_ISSUER_TOKEN_SOURCES_PER_REALM, Result, Verifier,
};

/// Separate committed abuse admission. It owns no client/user authority and is
/// complete before any current-client/source/owner/session lock is acquired.
pub(super) async fn admit(
    store: &Postgres,
    authority: &IssuerAuthority,
    source: Verifier,
) -> Result<()> {
    let realm = authority.realm();
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':issuer_token_admission',0))")
        .bind(realm).execute(&mut *tx).await.map_err(unavailable)?;
    let window: i64 = sqlx::query_scalar(
        "SELECT floor(extract(epoch FROM clock_timestamp())/$1::bigint)::bigint",
    )
    .bind(ISSUER_TOKEN_RATE_WINDOW_SECONDS)
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    sqlx::query("DELETE FROM auth_issuer_token_admission WHERE realm_id=$1 AND window_id<>$2")
        .bind(realm)
        .bind(window)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    let (keys, existing): (i64, bool) = sqlx::query_as("SELECT count(*),coalesce(bool_or(source_hash=$2),false) FROM auth_issuer_token_admission WHERE realm_id=$1 AND window_id=$3")
        .bind(realm).bind(source.as_slice()).bind(window).fetch_one(&mut *tx).await.map_err(unavailable)?;
    if !existing && keys >= MAX_ISSUER_TOKEN_SOURCES_PER_REALM {
        return Err(Error::RateLimited);
    }
    let attempt: Option<i64> = sqlx::query_scalar(
        r#"
            INSERT INTO auth_issuer_token_admission(realm_id,source_hash,window_id,attempts)
            VALUES($1,$2,$3,1)
            ON CONFLICT(realm_id,source_hash,window_id)
            DO UPDATE
            SET attempts=auth_issuer_token_admission.attempts+1
            WHERE auth_issuer_token_admission.attempts<$4
            RETURNING attempts
        "#,
    )
    .bind(realm)
    .bind(source.as_slice())
    .bind(window)
    .bind(ISSUER_TOKEN_ATTEMPTS_PER_MINUTE)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    if attempt.is_none() {
        return Err(Error::RateLimited);
    }
    tx.commit().await.map_err(unavailable)
}
