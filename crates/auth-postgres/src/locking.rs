use crate::unavailable;
use auth_core::{Error, Result, Verifier};
use uuid::Uuid;

// Serialize email proof issuance/consumption and reset, including account-creation races.
// The PostgreSQL hash is a lock key, not a credential/cryptographic verifier.
pub(crate) async fn lock_email(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    email: &str,
) -> Result<()> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':' || $2::text,0))",
    )
    .bind(realm)
    .bind(email)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    Ok(())
}
pub(crate) async fn lock_emails(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    old: &str,
    new: &str,
) -> Result<()> {
    let (first, second) = if old < new { (old, new) } else { (new, old) };
    lock_email(tx, realm, first).await?;
    if first != second {
        lock_email(tx, realm, second).await?;
    }
    Ok(())
}
pub(crate) async fn fresh_account(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    current: Verifier,
    email: &str,
) -> Result<(Uuid, Uuid)> {
    let user: Uuid =
        sqlx::query_scalar("SELECT id FROM auth_users WHERE realm_id=$1 AND email=$2 AND authentication_policy='mailbox' FOR UPDATE")
            .bind(realm)
            .bind(email)
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?
            .ok_or(Error::Unauthorized)?;
    let session = fresh_session(tx, realm, user, current).await?;
    Ok((user, session))
}

/// Caller must already hold this user's row lock. Keep user-before-session ordering
/// and evaluate freshness only after waiting for the user lock.
pub(crate) async fn fresh_session(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    user: Uuid,
    current: Verifier,
) -> Result<Uuid> {
    sqlx::query_scalar(
        r#"
        SELECT id
        FROM auth_sessions
        WHERE realm_id=$1
        AND user_id=$2
        AND token_hash=$3
        AND revoked_at IS NULL
        AND expires_at>clock_timestamp()
        AND last_seen_at>clock_timestamp()-interval '30 minutes'
        AND authenticated_at>clock_timestamp()-interval '5 minutes'
        AND authenticated_at<=clock_timestamp()
        AND authentication_method NOT IN ('oidc','saml')
        AND EXISTS (SELECT 1 FROM auth_users owner
            WHERE owner.realm_id=$1 AND owner.id=$2
              AND (owner.authentication_policy='mailbox'
                OR (owner.authentication_policy='passkey_required'
                    AND auth_sessions.authentication_method='passkey')))
        FOR
        UPDATE
        "#,
    )
    .bind(realm)
    .bind(user)
    .bind(current.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)
}
