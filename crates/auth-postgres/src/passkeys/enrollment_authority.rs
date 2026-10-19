use super::policy::fresh_owner;
use crate::{deadlines::Deadline, unavailable};
use auth_core::{Result, Verifier, authorize_passkey_enrollment};
use sqlx::Transaction;
use uuid::Uuid;

pub(super) struct Owner {
    pub user: Uuid,
    pub session: Uuid,
    pub account_name: String,
    pub deadline: Deadline,
}

/// Existing issuer/mutation paths serialize on this owner before locking sessions
/// or credentials. Re-read realm-wide key presence and exact method after both waits.
pub(super) async fn lock(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    current: Verifier,
) -> Result<Owner> {
    let (user, session, account_name) = fresh_owner(tx, realm, current).await?;
    let (method, owns_passkey): (String, bool) = sqlx::query_as(
        r#"
        SELECT s.authentication_method,
            EXISTS(SELECT 1 FROM auth_passkeys k WHERE k.realm_id=$1 AND k.user_id=$2)
        FROM auth_sessions s WHERE s.realm_id=$1 AND s.user_id=$2 AND s.id=$3
        "#,
    )
    .bind(realm)
    .bind(user)
    .bind(session)
    .fetch_one(&mut **tx)
    .await
    .map_err(unavailable)?;
    authorize_passkey_enrollment(&method, owns_passkey)?;
    let deadline = Deadline::fresh_session(tx, realm, user, session).await?;
    Ok(Owner {
        user,
        session,
        account_name,
        deadline,
    })
}
