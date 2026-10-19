use super::admission::admit;
use crate::{audit, unavailable};
use auth_core::{
    AuditEvent, Error, PasskeySignupRequest, PrivatePasskeyAuthentication, Result, StoredPasskey,
    VerifiedPasskeyAuthentication, Verifier,
};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn load(
    pool: &PgPool,
    request: &PasskeySignupRequest,
    rp_id: &str,
) -> Result<(PrivatePasskeyAuthentication, StoredPasskey)> {
    admit(pool, request, true).await?;
    let (owner, state, id, candidate): (Uuid, Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
        r#"
        SELECT prospective_user,authentication_state,candidate_id,candidate
        FROM auth_passkey_signups WHERE realm_id=$1 AND id=$2 AND browser_hash=$3 AND rp_id=$4
          AND stage='assertion' AND expires_at>clock_timestamp()
        "#,
    )
    .bind(request.realm)
    .bind(request.transaction)
    .bind(request.browser.as_slice())
    .bind(rp_id)
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    let state = PrivatePasskeyAuthentication::decode_from_database(&state)?;
    if state.realm() != request.realm || state.owner() != Some(owner) {
        return Err(Error::Unauthorized);
    }
    Ok((
        state,
        StoredPasskey::decode_from_database(request.realm, owner, rp_id, &id, &candidate)?,
    ))
}

pub(super) async fn commit(
    pool: &PgPool,
    request: &PasskeySignupRequest,
    proof: VerifiedPasskeyAuthentication,
    session: Verifier,
) -> Result<()> {
    if proof.realm() != request.realm {
        return Err(Error::Unauthorized);
    }
    let state =
        PrivatePasskeyAuthentication::decode_from_database(proof.expected_state_for_database())?;
    if state.owner() != Some(proof.user_id()) || state.purpose() != "account_bound" {
        return Err(Error::Unauthorized);
    }
    let mut tx = pool.begin().await.map_err(unavailable)?;
    // No persistent owner exists yet. This dedicated pending row serializes signup;
    // normal user/key lifecycle transactions never acquire a pending-signup lock.
    let locked: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM auth_passkey_signups WHERE realm_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(request.realm)
    .bind(request.transaction)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    locked.ok_or(Error::Unauthorized)?;
    let display_name: String = sqlx::query_scalar(
        r#"
        SELECT display_name FROM auth_passkey_signups
        WHERE realm_id=$1 AND id=$2 AND browser_hash=$3 AND rp_id=$4
          AND prospective_user=$5 AND authentication_state=$6 AND candidate=$7 AND candidate_id=$8
          AND stage='assertion' AND expires_at>clock_timestamp()
        "#,
    )
    .bind(request.realm)
    .bind(request.transaction)
    .bind(request.browser.as_slice())
    .bind(proof.rp_id())
    .bind(proof.user_id())
    .bind(proof.expected_state_for_database())
    .bind(proof.expected_credential_for_database())
    .bind(proof.credential_id())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    let owner: Option<Uuid> = sqlx::query_scalar(
        r#"
        INSERT INTO auth_users(realm_id,id,email,email_verified_at,display_name,authentication_policy)
        VALUES ($1,$2,NULL,NULL,$3,'passkey_required') ON CONFLICT DO NOTHING RETURNING id
        "#,
    )
    .bind(request.realm)
    .bind(proof.user_id())
    .bind(display_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    owner.ok_or(Error::Unauthorized)?;
    let credential: Option<Uuid> = sqlx::query_scalar(
        r#"
        INSERT INTO auth_passkeys(realm_id,id,user_id,rp_id,credential_id,credential,label,last_used_at)
        VALUES ($1,$2,$3,$4,$5,$6,'Initial passkey',clock_timestamp())
        ON CONFLICT DO NOTHING RETURNING id
        "#,
    )
    .bind(request.realm)
    .bind(Uuid::new_v4())
    .bind(proof.user_id())
    .bind(proof.rp_id())
    .bind(proof.credential_id())
    .bind(proof.updated_credential_for_database())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    credential.ok_or(Error::Unauthorized)?;
    let session_id = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,'passkey')")
        .bind(request.realm).bind(session_id).bind(proof.user_id()).bind(session.as_slice())
        .execute(&mut *tx).await.map_err(unavailable)?;
    audit::record(
        &mut tx,
        request.realm,
        AuditEvent::PasskeySignedUp {
            user_id: proof.user_id(),
            session_id,
        },
    )
    .await?;
    // Final consumption follows ALL potentially blocking writes, including session
    // uniqueness and audit/FK waits. Expiry rolls every insert back together.
    let consumed: Option<Uuid> = sqlx::query_scalar(
        r#"
        DELETE FROM auth_passkey_signups WHERE realm_id=$1 AND id=$2 AND browser_hash=$3
          AND stage='assertion' AND expires_at>clock_timestamp()
        RETURNING id
        "#,
    )
    .bind(request.realm)
    .bind(request.transaction)
    .bind(request.browser.as_slice())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    consumed.ok_or(Error::Unauthorized)?;
    tx.commit().await.map_err(unavailable)
}
