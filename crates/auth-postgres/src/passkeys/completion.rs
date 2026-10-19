use super::{
    enrollment_authority,
    policy::{admit, credential_limit},
};
use crate::{audit, unavailable};
use auth_core::{
    AuditEvent, Error, PasskeyEnrollmentRequest, PrivatePasskeyRegistration, Result,
    VerifiedPasskey,
};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn load(
    pool: &PgPool,
    request: &PasskeyEnrollmentRequest,
) -> Result<PrivatePasskeyRegistration> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let owner = enrollment_authority::lock(&mut tx, request.realm, request.session).await?;
    let (user, session) = (owner.user, owner.session);
    admit(&mut tx, request.realm, user, request.source, true).await?;
    let state: Option<Vec<u8>> = sqlx::query_scalar(
        r#"
        SELECT private_state FROM auth_passkey_enrollments
        WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND session_id=$4
          AND browser_hash=$5 AND expires_at>clock_timestamp()
        "#,
    )
    .bind(request.realm)
    .bind(request.transaction)
    .bind(user)
    .bind(session)
    .bind(request.browser.as_slice())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    // Persist admission even when the ceremony is absent/invalid; repeated failures spend budget.
    owner.deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    PrivatePasskeyRegistration::decode_from_database(&state.ok_or(Error::Unauthorized)?)
}

pub(super) async fn commit(
    pool: &PgPool,
    request: &PasskeyEnrollmentRequest,
    expected_state: &[u8],
    credential: VerifiedPasskey,
) -> Result<Uuid> {
    let encoded = credential.encode_for_database()?;
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let owner = enrollment_authority::lock(&mut tx, request.realm, request.session).await?;
    let (user, session) = (owner.user, owner.session);
    credential_limit(&mut tx, request.realm, user, credential.rp_id()).await?;
    let (label, expires_us): (String, i64) = sqlx::query_as(
        r#"
        SELECT label,(extract(epoch FROM expires_at)*1000000)::bigint FROM auth_passkey_enrollments
        WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND session_id=$4
          AND browser_hash=$5 AND expires_at>clock_timestamp()
          AND rp_id=$6 AND private_state=$7
        FOR UPDATE
        "#,
    )
    .bind(request.realm)
    .bind(request.transaction)
    .bind(user)
    .bind(session)
    .bind(request.browser.as_slice())
    .bind(credential.rp_id())
    .bind(expected_state)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    let deadline = owner.deadline.with_proof(expires_us);
    let id = Uuid::new_v4();
    let inserted = sqlx::query(
        r#"
        INSERT INTO auth_passkeys(realm_id,id,user_id,rp_id,credential_id,credential,label)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (rp_id,credential_id) DO NOTHING
        "#,
    )
    .bind(request.realm)
    .bind(id)
    .bind(user)
    .bind(credential.rp_id())
    .bind(credential.credential_id())
    .bind(encoded)
    .bind(label)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    if inserted.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    audit::record(
        &mut tx,
        request.realm,
        AuditEvent::PasskeyEnrolled {
            user_id: user,
            actor_session_id: session,
        },
    )
    .await?;
    // User, initiating session and pending row remain locked. Authorization and
    // exact state were checked above, but key uniqueness/audit writes can block.
    // Consume only after those writes, with both deadlines evaluated now. Any
    // miss rolls back credential, audit and proof consumption together.
    let consumed = sqlx::query(
        r#"
        DELETE FROM auth_passkey_enrollments p USING auth_sessions s
        WHERE p.realm_id=$1 AND p.id=$2 AND p.user_id=$3 AND p.session_id=$4
          AND p.browser_hash=$5 AND p.rp_id=$6 AND p.private_state=$7
          AND p.expires_at>clock_timestamp()
          AND s.realm_id=p.realm_id AND s.id=p.session_id AND s.user_id=p.user_id
          AND s.token_hash=$8 AND s.revoked_at IS NULL
          AND s.authenticated_at>clock_timestamp()-interval '5 minutes'
          AND s.authenticated_at<=clock_timestamp()
          AND s.expires_at>clock_timestamp()
          AND s.last_seen_at>clock_timestamp()-interval '30 minutes'
        "#,
    )
    .bind(request.realm)
    .bind(request.transaction)
    .bind(user)
    .bind(session)
    .bind(request.browser.as_slice())
    .bind(credential.rp_id())
    .bind(expected_state)
    .bind(request.session.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    if consumed.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(id)
}
