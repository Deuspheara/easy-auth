use crate::{Postgres, deadlines::Deadline, identity::user_from_row, unavailable};
use auth_core::{Error, Result, User, Verifier};
use sqlx::Transaction;
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn authenticate(&self, realm: Uuid, session: Verifier) -> Result<User> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let (user, _, deadline) = active_caller(&mut tx, realm, session).await?;
        deadline.check(&mut tx).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(user)
    }
}

/// Lock owner before session, then validate in a new statement after both waits.
/// Shared owner locks permit independent validations while excluding policy and
/// credential mutations. Capture the original idle deadline before touching it.
pub(super) async fn active_caller(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    current: Verifier,
) -> Result<(User, Uuid, Deadline)> {
    let source = super::source::Source::lock(tx, realm, current).await?;
    let user: Uuid = sqlx::query_scalar(
        r#"
        SELECT u.id FROM auth_users u
        JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id
        WHERE s.realm_id=$1 AND s.token_hash=$2 FOR SHARE OF u
        "#,
    )
    .bind(realm)
    .bind(current.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    let session: Uuid = sqlx::query_scalar(
        "SELECT id FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND token_hash=$3 FOR UPDATE",
    )
    .bind(realm)
    .bind(user)
    .bind(current.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    #[cfg(any(feature = "oidc-identities", feature = "saml-identities"))]
    source.recheck(tx, realm, current).await?;
    let row = sqlx::query(
        r#"
        SELECT u.id,u.email,u.display_name,u.authentication_policy
        FROM auth_users u JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id
        WHERE u.realm_id=$1 AND u.id=$2 AND s.id=$3 AND s.revoked_at IS NULL
          AND s.expires_at>clock_timestamp()
          AND s.last_seen_at>clock_timestamp()-interval '30 minutes'
          AND s.authentication_method=$4
        "#,
    )
    .bind(realm)
    .bind(user)
    .bind(session)
    .bind(source.method())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    let account = user_from_row(realm, &row)?;
    if !source
        .permits_policy(tx, realm, account.id, account.authentication_policy)
        .await?
    {
        return Err(Error::Unauthorized);
    }
    let deadline = Deadline::active_session(tx, realm, user, session).await?;
    sqlx::query("UPDATE auth_sessions SET last_seen_at=clock_timestamp() WHERE realm_id=$1 AND user_id=$2 AND id=$3")
        .bind(realm).bind(user).bind(session)
        .execute(&mut **tx).await.map_err(unavailable)?;
    Ok((account, session, deadline))
}
