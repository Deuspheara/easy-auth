use crate::{deadlines::Deadline, locking::lock_email, unavailable};
use auth_core::{Error, OAuthConnection, Result, Verifier};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Caller keeps this transaction's configuration/policy/owner/session/identity
/// locks and must recheck the captured deadline after later writes.
pub(crate) struct ProviderOwner {
    pub(crate) user: Uuid,
    pub(crate) session: Uuid,
    pub(super) identity: Uuid,
    pub(super) email: Option<String>,
    pub(crate) deadline: Deadline,
}

/// Configuration was locked and fully compared by the caller. Do not lock an
/// unrelated session source after it: a wrong connection rejects, avoiding an
/// attacker-selected second configuration lock and its possible order inversion.
pub(crate) async fn lock(
    tx: &mut Transaction<'_, Postgres>,
    c: &OAuthConnection,
    user: Uuid,
    current: Verifier,
) -> Result<ProviderOwner> {
    let policy: Option<Uuid> = sqlx::query_scalar("SELECT revision FROM auth_oidc_identity_policies WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND revision=$4 FOR SHARE")
        .bind(c.realm()).bind(c.connection()).bind(c.client()).bind(c.revision())
        .fetch_optional(&mut **tx).await.map_err(unavailable)?;
    if policy != Some(c.revision()) {
        return Err(Error::Unauthorized);
    }
    // Only select the email lock path here. No snapshot is authorization.
    let email: Option<String> =
        sqlx::query_scalar("SELECT email FROM auth_users WHERE realm_id=$1 AND id=$2")
            .bind(c.realm())
            .bind(user)
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?
            .ok_or(Error::Unauthorized)?;
    if let Some(email) = &email {
        lock_email(tx, c.realm(), email).await?;
    }
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 AND authentication_policy='provider_required' AND email IS NOT DISTINCT FROM $3::text FOR UPDATE")
        .bind(c.realm()).bind(user).bind(&email).fetch_optional(&mut **tx).await.map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
    let (session, identity): (Uuid, Uuid) = sqlx::query_as(
        r#"
        SELECT s.id,e.id FROM auth_sessions s JOIN auth_oidc_identities e
          ON e.realm_id=s.realm_id AND e.id=s.oidc_identity_id AND e.user_id=s.user_id
        WHERE s.realm_id=$1 AND s.user_id=$2 AND s.token_hash=$3
          AND s.authentication_method='oidc' AND s.oidc_revision=$4
          AND e.connection_id=$5 AND e.client_id=$6 AND e.issuer=$7
          AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
          AND s.last_seen_at>clock_timestamp()-interval '30 minutes'
        FOR UPDATE OF s
    "#,
    )
    .bind(c.realm())
    .bind(user)
    .bind(current.as_slice())
    .bind(c.revision())
    .bind(c.connection())
    .bind(c.client())
    .bind(c.issuer())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    let deadline = Deadline::active_session(tx, c.realm(), user, session).await?;
    // Retain the exact subject source as well as the owner/session. Re-read after
    // the wait rather than promoting a previously observed row into authority.
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM auth_oidc_identities WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND connection_id=$4 AND client_id=$5 AND issuer=$6 FOR UPDATE")
        .bind(c.realm()).bind(identity).bind(user).bind(c.connection()).bind(c.client()).bind(c.issuer())
        .fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
    deadline.check(tx).await?;
    Ok(ProviderOwner {
        user,
        session,
        identity,
        email,
        deadline,
    })
}
