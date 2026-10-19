use super::{authorization, invalidation};
use crate::{audit, unavailable};
use auth_core::{
    AuditEvent, Error, PasskeyRecoveryReplacementRequest, PrivatePasskeyAuthentication, Result,
    StoredPasskey, VerifiedPasskeyAuthentication, Verifier,
};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn load(
    pool: &PgPool,
    request: &PasskeyRecoveryReplacementRequest,
) -> Result<(PrivatePasskeyAuthentication, StoredPasskey)> {
    let c = &request.claim;
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let deadline = authorization::ready(&mut tx, request).await?;
    let deadline = authorization::pending(&mut tx, request, deadline).await?;
    let (state, id, candidate): (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
        r#"
        SELECT authentication_state,candidate_id,candidate
        FROM auth_passkey_recovery_replacements
        WHERE realm_id=$1
        AND claim_id=$2
        AND id=$3
        AND stage='assertion'
        "#,
    )
    .bind(c.realm)
    .bind(request.claim_id)
    .bind(request.transaction)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    let state = PrivatePasskeyAuthentication::decode_from_database(&state)?;
    if state.realm() != c.realm
        || state.owner() != Some(c.user_id)
        || state.purpose() != "account_bound"
    {
        return Err(Error::Unauthorized);
    }
    let candidate =
        StoredPasskey::decode_from_database(c.realm, c.user_id, &c.rp_id, &id, &candidate)?;
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok((state, candidate))
}

pub(super) async fn commit(
    pool: &PgPool,
    request: &PasskeyRecoveryReplacementRequest,
    proof: VerifiedPasskeyAuthentication,
    session: Verifier,
) -> Result<()> {
    let c = &request.claim;
    if proof.realm() != c.realm || proof.user_id() != c.user_id || proof.rp_id() != c.rp_id {
        return Err(Error::Unauthorized);
    }
    let state =
        PrivatePasskeyAuthentication::decode_from_database(proof.expected_state_for_database())?;
    if state.owner() != Some(c.user_id) || state.purpose() != "account_bound" {
        return Err(Error::Unauthorized);
    }
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let deadline = authorization::ready_for_commit(&mut tx, request).await?;
    let deadline = authorization::pending(&mut tx, request, deadline).await?;
    let exact: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(SELECT 1
        FROM auth_passkey_recovery_replacements
        WHERE realm_id=$1
        AND claim_id=$2
        AND id=$3
        AND stage='assertion'
        AND authentication_state=$4
        AND candidate=$5
        AND candidate_id=$6)
        "#,
    )
    .bind(c.realm)
    .bind(request.claim_id)
    .bind(request.transaction)
    .bind(proof.expected_state_for_database())
    .bind(proof.expected_credential_for_database())
    .bind(proof.credential_id())
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    if !exact {
        return Err(Error::Unauthorized);
    }
    let key = Uuid::new_v4();
    // Insert before deleting old keys: RP-wide uniqueness, including another
    // realm or an existing owned key, must reject instead of transferring identity.
    let inserted: Option<Uuid> = sqlx::query_scalar(
        r#"
        INSERT INTO auth_passkeys(realm_id,id,user_id,rp_id,credential_id,credential,label,last_used_at)
        VALUES ($1,$2,$3,$4,$5,$6,'Recovered passkey',clock_timestamp())
        ON CONFLICT DO NOTHING
        RETURNING id
        "#,
    )
    .bind(c.realm)
    .bind(key)
    .bind(c.user_id)
    .bind(&c.rp_id)
    .bind(proof.credential_id())
    .bind(proof.updated_credential_for_database())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    inserted.ok_or(Error::Unauthorized)?;
    invalidation::revoke(&mut tx, c.realm, c.user_id, key).await?;
    let session_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method)
        VALUES ($1,$2,$3,$4,'passkey')
        "#,
    )
    .bind(c.realm)
    .bind(session_id)
    .bind(c.user_id)
    .bind(session.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    audit::record(
        &mut tx,
        c.realm,
        AuditEvent::PasskeyRecovered {
            user_id: c.user_id,
            claim_id: request.claim_id,
            session_id,
        },
    )
    .await?;
    sqlx::query("DELETE FROM auth_security_notifications WHERE realm_id=$1 AND user_id=$2 AND recovery_claim_id=$3")
        .bind(c.realm)
        .bind(c.user_id)
        .bind(request.claim_id)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    sqlx::query(
        r#"
        INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind) SELECT realm_id,$3,id,email,'passkey_recovery_completed'
        FROM auth_users
        WHERE realm_id=$1
        AND id=$2
        AND email IS NOT NULL
        AND email_verified_at IS NOT NULL
        "#,
        )
        .bind(c.realm)
        .bind(c.user_id)
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("DELETE FROM auth_passkey_recovery_replacements WHERE realm_id=$1 AND claim_id=$2")
        .bind(c.realm)
        .bind(request.claim_id)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    sqlx::query(
        r#"
        UPDATE auth_passkey_recovery_claims
        SET completed_at=clock_timestamp()
        WHERE realm_id=$1
        AND id=$2
        AND user_id=$3
        "#,
    )
    .bind(c.realm)
    .bind(request.claim_id)
    .bind(c.user_id)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)
}
