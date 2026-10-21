use crate::unavailable;
use auth_core::{AuthenticationPolicy, Result, User};
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;

pub(crate) fn user_from_row(realm: Uuid, row: &PgRow) -> Result<User> {
    let policy: &str = row.try_get("authentication_policy").map_err(unavailable)?;
    Ok(User {
        id: row.try_get("id").map_err(unavailable)?,
        realm_id: realm,
        email: row.try_get("email").map_err(unavailable)?,
        display_name: row.try_get("display_name").map_err(unavailable)?,
        authentication_policy: AuthenticationPolicy::try_from(policy)?,
    })
}

/// Caller already holds source/policy and scoped subject serialization. Preserve
/// email -> owner lock order and the original email snapshot; a vanished/changed
/// owner is rejected and cannot fall through to creating a replacement account.
#[cfg(feature = "oidc-identities")]
pub(crate) async fn lock_provider_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    user: Uuid,
    email: Option<&str>,
) -> Result<User> {
    if let Some(email) = email {
        crate::locking::lock_email(tx, realm, email).await?;
    }
    let row = sqlx::query(
        "SELECT id,email,display_name,authentication_policy FROM auth_users WHERE realm_id=$1 AND id=$2 AND email IS NOT DISTINCT FROM $3::text FOR UPDATE"
    ).bind(realm).bind(user).bind(email)
        .fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(auth_core::Error::Unauthorized)?;
    let user = user_from_row(realm, &row)?;
    if user.authentication_policy != AuthenticationPolicy::ProviderRequired {
        return Err(auth_core::Error::Unauthorized);
    }
    Ok(user)
}
