use super::{clock, state::AuthorizationState};
use crate::{
    audit, deadlines::Deadline, issuer::subjects, sessions::FreshSessionAuthorization, unavailable,
};
use auth_core::{
    AuditEvent, Error, ISSUER_CODE_LIFETIME_SECONDS, IssuerClientRegistration, IssuerConsentProof,
    Result, Verifier,
};
use sqlx::{Postgres as Pg, Transaction};

/// Caller holds current client, source, owner, fresh session and pending consent.
/// This writes one approval/audit in that caller-owned transaction, never commits.
pub(super) async fn approve(
    tx: &mut Transaction<'_, Pg>,
    proof: &IssuerConsentProof<'_>,
    code: Verifier,
    client: &IssuerClientRegistration,
    state: &AuthorizationState,
    caller: &FreshSessionAuthorization,
    deadline: &Deadline,
) -> Result<(i64, i64)> {
    let now = clock::now(tx).await?;
    let expiry = now
        .checked_add(ISSUER_CODE_LIFETIME_SECONDS * 1_000_000)
        .ok_or(Error::Unavailable)?
        .min(deadline.expires_us());
    if expiry <= now {
        return Err(Error::Unauthorized);
    }
    let subject = subjects::allocate_for_locked_client(tx, client, caller.user).await?;
    sqlx::query(
        r#"
            UPDATE auth_issuer_authorizations
            SET status='approved',subject=$3,code_hash=$4,approved_at_us=$5,code_expires_at_us=$6
            WHERE realm_id=$1
            AND id=$2
            AND status='pending'
        "#,
    )
    .bind(proof.authority.realm())
    .bind(state.id)
    .bind(subject)
    .bind(code.as_slice())
    .bind(now)
    .bind(expiry)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    audit::record(
        tx,
        proof.authority.realm(),
        AuditEvent::IssuerAuthorized {
            user_id: caller.user,
            actor_session_id: caller.session,
            client_id: client.client(),
            authorization_id: state.id,
        },
    )
    .await?;
    Ok((now, expiry))
}
