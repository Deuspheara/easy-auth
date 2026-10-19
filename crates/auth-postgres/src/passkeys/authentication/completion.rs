use super::admission::admit;
use crate::{audit, unavailable};
use auth_core::{
    AuditEvent, Error, PasskeyAuthenticationRequest, PrivatePasskeyAuthentication, Result,
    StoredPasskey, VerifiedPasskeyAuthentication, Verifier,
};
use sqlx::PgPool;
use uuid::Uuid;

const MAX_CREDENTIAL_ID_BYTES: usize = 1024;

pub(super) async fn load(
    pool: &PgPool,
    request: &PasskeyAuthenticationRequest,
    rp_id: &str,
    credential_id: &[u8],
) -> Result<(PrivatePasskeyAuthentication, StoredPasskey)> {
    admit(pool, request, true).await?;
    if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID_BYTES {
        return Err(Error::Unauthorized);
    }
    let row: Option<(Vec<u8>, Uuid, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT a.private_state,p.user_id,p.credential
        FROM auth_passkey_authentications a
        JOIN auth_passkeys p ON p.realm_id=a.realm_id AND p.rp_id=a.rp_id AND p.credential_id=$5
        WHERE a.realm_id=$1 AND a.id=$2 AND a.browser_hash=$3 AND a.rp_id=$4
          AND a.expires_at>clock_timestamp()
          AND ((a.purpose='account_bound' AND a.user_id=p.user_id)
            OR (a.purpose='discoverable' AND a.user_id IS NULL))
    "#,
    )
    .bind(request.realm)
    .bind(request.transaction)
    .bind(request.browser.as_slice())
    .bind(rp_id)
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?;
    let (state, owner, encoded) = row.ok_or(Error::Unauthorized)?;
    Ok((
        PrivatePasskeyAuthentication::decode_from_database(&state)?,
        StoredPasskey::decode_from_database(request.realm, owner, rp_id, credential_id, &encoded)?,
    ))
}

pub(super) async fn commit(
    pool: &PgPool,
    request: &PasskeyAuthenticationRequest,
    proof: VerifiedPasskeyAuthentication,
    session: Verifier,
) -> Result<()> {
    if proof.realm() != request.realm {
        return Err(Error::Unauthorized);
    }
    let state =
        PrivatePasskeyAuthentication::decode_from_database(proof.expected_state_for_database())?;
    let mut tx = pool.begin().await.map_err(unavailable)?;
    // Every issuer and lifecycle mutation serializes on the owner first. Recheck
    // all mutable proof state and clock time after waiting; no stale verification write.
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
            .bind(request.realm)
            .bind(proof.user_id())
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
    let owner = owner.ok_or(Error::Unauthorized)?;
    let current: Option<Vec<u8>> = sqlx::query_scalar(
        r#"
        SELECT credential FROM auth_passkeys
        WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND credential_id=$4 FOR UPDATE
    "#,
    )
    .bind(request.realm)
    .bind(owner)
    .bind(proof.rp_id())
    .bind(proof.credential_id())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    if current.as_deref() != Some(proof.expected_credential_for_database()) {
        return Err(Error::Unauthorized);
    }
    // Lock separately so the following statement evaluates clock_timestamp after
    // any ceremony-row wait, including a lock holder that makes no row update.
    let pending: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM auth_passkey_authentications WHERE realm_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(request.realm)
    .bind(request.transaction)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    pending.ok_or(Error::Unauthorized)?;
    let consumed: Option<Uuid> = sqlx::query_scalar(
        r#"
        DELETE FROM auth_passkey_authentications
        WHERE realm_id=$1 AND id=$2 AND browser_hash=$3 AND rp_id=$4
          AND private_state=$5 AND expires_at>clock_timestamp() AND purpose=$6
          AND user_id IS NOT DISTINCT FROM $7
        RETURNING id
    "#,
    )
    .bind(request.realm)
    .bind(request.transaction)
    .bind(request.browser.as_slice())
    .bind(proof.rp_id())
    .bind(proof.expected_state_for_database())
    .bind(state.purpose())
    .bind(state.owner())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    consumed.ok_or(Error::Unauthorized)?;
    sqlx::query(
        r#"
        UPDATE auth_passkeys SET credential=$5,last_used_at=clock_timestamp()
        WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND credential_id=$4
    "#,
    )
    .bind(request.realm)
    .bind(owner)
    .bind(proof.rp_id())
    .bind(proof.credential_id())
    .bind(proof.updated_credential_for_database())
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    let session_id = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,'passkey')")
        .bind(request.realm).bind(session_id).bind(owner).bind(session.as_slice())
        .execute(&mut *tx).await.map_err(unavailable)?;
    audit::record(
        &mut tx,
        request.realm,
        AuditEvent::PasskeyAuthenticated {
            user_id: owner,
            session_id,
        },
    )
    .await?;
    tx.commit().await.map_err(unavailable)
}
