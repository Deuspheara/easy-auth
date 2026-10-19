use super::policy::{admit, credential_limit, fresh_owner};
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
    let (user, session, _) = fresh_owner(&mut tx, request.realm, request.session).await?;
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
    let (user, session, _) = fresh_owner(&mut tx, request.realm, request.session).await?;
    credential_limit(&mut tx, request.realm, user, credential.rp_id()).await?;
    let label: String = sqlx::query_scalar(
        r#"
        DELETE FROM auth_passkey_enrollments
        WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND session_id=$4
          AND browser_hash=$5 AND expires_at>clock_timestamp()
          AND rp_id=$6 AND private_state=$7
        RETURNING label
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
    tx.commit().await.map_err(unavailable)?;
    Ok(id)
}
