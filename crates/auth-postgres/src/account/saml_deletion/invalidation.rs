use crate::unavailable;
use auth_core::Result;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Caller already holds the owning user/session locks. Cancel only local bound
/// deletion state; never acquire source locks after the owner or consume sign-in.
pub(crate) async fn cancel_saml_deletion_session_requests(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    user: Uuid,
    session: Uuid,
) -> Result<()> {
    sqlx::query("DELETE FROM auth_saml_requests WHERE realm_id=$1 AND user_id=$2 AND session_id=$3 AND purpose='delete_account'")
        .bind(realm).bind(user).bind(session).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}

pub(crate) async fn cancel_saml_deletion_owner_requests(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    user: Uuid,
) -> Result<()> {
    sqlx::query("DELETE FROM auth_saml_requests WHERE realm_id=$1 AND user_id=$2 AND purpose='delete_account'")
        .bind(realm).bind(user).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}
