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
