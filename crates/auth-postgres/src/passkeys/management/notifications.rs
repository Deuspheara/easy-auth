use crate::unavailable;
use auth_core::Result;
use sqlx::Transaction;
use uuid::Uuid;

pub(super) async fn notify(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    user: Uuid,
) -> Result<()> {
    // The owner lock freezes the established verified recipient. Never invent one.
    sqlx::query(
        "INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind) SELECT realm_id,$3,id,email,'passkeys_changed' FROM auth_users WHERE realm_id=$1 AND id=$2 AND email IS NOT NULL AND email_verified_at IS NOT NULL",
    ).bind(realm).bind(user).bind(Uuid::new_v4())
        .execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}
