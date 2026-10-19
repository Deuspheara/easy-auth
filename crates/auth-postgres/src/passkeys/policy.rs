use crate::{locking::fresh_session, unavailable};
use auth_core::{Error, MAX_PASSKEYS_PER_ACCOUNT, Result, Verifier};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

const ENROLLMENT_ATTEMPTS_PER_USER: i32 = 10;
const VERIFICATION_ATTEMPTS_PER_USER: i32 = 20;
const ATTEMPTS_PER_SOURCE: i32 = 40;

/// User-before-session ordering matches credential mutation and session revocation.
pub(super) async fn fresh_owner(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    current: Verifier,
) -> Result<(Uuid, Uuid, String)> {
    let (user, account_name): (Uuid, String) = sqlx::query_as(
        r#"
        SELECT u.id,coalesce(u.email,u.display_name) FROM auth_users u
        JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id
        WHERE s.realm_id=$1 AND s.token_hash=$2
        FOR UPDATE OF u
        "#,
    )
    .bind(realm)
    .bind(current.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    let session = fresh_session(tx, realm, user, current).await?;
    Ok((user, session, account_name))
}

pub(super) async fn credential_limit(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    user: Uuid,
    rp: &str,
) -> Result<()> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_passkeys WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3",
    )
    .bind(realm)
    .bind(user)
    .bind(rp)
    .fetch_one(&mut **tx)
    .await
    .map_err(unavailable)?;
    if count >= MAX_PASSKEYS_PER_ACCOUNT as i64 {
        return Err(Error::RateLimited);
    }
    Ok(())
}

pub(super) async fn admit(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    user: Uuid,
    source: Verifier,
    completion: bool,
) -> Result<()> {
    let (user_dimension, source_dimension, user_limit) = if completion {
        (
            "passkey_finish_user",
            "passkey_finish_source",
            VERIFICATION_ATTEMPTS_PER_USER,
        )
    } else {
        (
            "passkey_enroll_user",
            "passkey_enroll_source",
            ENROLLMENT_ATTEMPTS_PER_USER,
        )
    };
    for (dimension, key, limit) in [
        (user_dimension, user.as_bytes().as_slice(), user_limit),
        (source_dimension, source.as_slice(), ATTEMPTS_PER_SOURCE),
    ] {
        let admitted = sqlx::query_scalar::<_, i32>(
            r#"
            INSERT INTO auth_rate_buckets(realm_id,dimension,key_hash,window_id,attempts)
            VALUES ($1,$2,sha256($3),floor(extract(epoch FROM clock_timestamp())/600)::bigint,1)
            ON CONFLICT (realm_id,dimension,key_hash,window_id) DO UPDATE
            SET attempts=auth_rate_buckets.attempts+1
            WHERE auth_rate_buckets.attempts<$4
            RETURNING attempts
            "#,
        )
        .bind(realm)
        .bind(dimension)
        .bind(key)
        .bind(limit)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?;
        if admitted.is_none() {
            return Err(Error::RateLimited);
        }
    }
    Ok(())
}
