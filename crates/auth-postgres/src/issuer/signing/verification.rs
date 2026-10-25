use super::state::KeyRow;
use crate::unavailable;
use auth_core::{IssuerAuthority, Result};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Retained verification authority, not active signing selection. Old unexpired
/// tokens survive an ordinary rotation, but not key/namespace disable or an
/// unpropagated reenable. Caller holds client lock before this namespace/key lock.
pub(in crate::issuer) async fn lock_retained_key(
    tx: &mut Transaction<'_, Postgres>,
    authority: &IssuerAuthority,
    key: Uuid,
    issued: i64,
    expires: i64,
) -> Result<bool> {
    let row: Option<KeyRow> = sqlx::query_as(r#"
        SELECT k.id,k.public_jwk,k.sign_from_us,k.sign_until_us,k.verify_until_us,k.ready_at_us,k.enabled
        FROM auth_issuer_key_sets s JOIN auth_issuer_keys k ON k.realm_id=s.realm_id AND k.issuer=s.issuer
        WHERE s.realm_id=$1 AND s.issuer=$2 AND k.id=$3 AND s.enabled AND k.enabled
          AND k.ready_at_us<=(extract(epoch FROM clock_timestamp())*1000000)::bigint
          AND k.sign_from_us<=$4 AND k.sign_until_us>$4 AND k.verify_until_us>=$5
          AND $5>(extract(epoch FROM clock_timestamp())*1000000)::bigint
        FOR SHARE OF s,k
    "#).bind(authority.realm()).bind(authority.issuer()).bind(key).bind(issued).bind(expires)
        .fetch_optional(&mut **tx).await.map_err(unavailable)?;
    match row {
        Some(row) => {
            row.publication(authority)?;
            Ok(true)
        }
        None => Ok(false),
    }
}
