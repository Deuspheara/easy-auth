use crate::unavailable;
use auth_core::Result;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    owner: Uuid,
) -> Result<()> {
    // Caller holds owner. Only the existing verified local contact is eligible;
    // unsigned/signed provider email never becomes a notification destination.
    sqlx::query("INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind) SELECT realm_id,$3,id,email,'providers_changed' FROM auth_users WHERE realm_id=$1 AND id=$2 AND email IS NOT NULL AND email_verified_at IS NOT NULL")
        .bind(realm).bind(owner).bind(Uuid::new_v4()).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}
