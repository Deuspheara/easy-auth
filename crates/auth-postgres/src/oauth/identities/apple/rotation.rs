use crate::{Postgres, unavailable};
use auth_core::{AppleGrantBinding, AppleGrantEnvelope, Error, Result};
use sqlx::Row;
use uuid::Uuid;
impl Postgres {
    /// Trusted key maintenance only. Never selected from a user/body credential.
    /// Skip busy/leased/finished rows, retain original job deadlines, and rewrap
    /// without changing the provider token or making a remote-success claim.
    pub async fn rotate_apple_grant_key(&self, realm: Uuid, grant: Uuid) -> Result<bool> {
        if realm.is_nil() || grant.is_nil() {
            return Err(Error::InvalidInput);
        }
        let vault = self.apple_grant_vault.as_ref().ok_or(Error::Unavailable)?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let row=sqlx::query("SELECT connection_id,client_id,binding_identity_id,key_id,ciphertext,version FROM auth_apple_grants WHERE realm_id=$1 AND id=$2 AND state IN ('active','pending','failed') FOR UPDATE SKIP LOCKED")
            .bind(realm).bind(grant).fetch_optional(&mut *tx).await.map_err(unavailable)?;
        let Some(row) = row else { return Ok(false) };
        let binding = AppleGrantBinding::new(
            realm,
            row.try_get("connection_id").map_err(unavailable)?,
            row.try_get("client_id").map_err(unavailable)?,
            row.try_get("binding_identity_id").map_err(unavailable)?,
            grant,
        )?;
        let envelope = AppleGrantEnvelope::restore(
            binding,
            row.try_get("key_id").map_err(unavailable)?,
            row.try_get("ciphertext").map_err(unavailable)?,
        )?;
        let replacement = vault.rewrap(&envelope).await?;
        let version: i64 = row.try_get("version").map_err(unavailable)?;
        let changed=sqlx::query("UPDATE auth_apple_grants SET key_id=$3,ciphertext=$4,version=version+1 WHERE realm_id=$1 AND id=$2 AND version=$5")
            .bind(realm).bind(grant).bind(replacement.key_id()).bind(replacement.ciphertext()).bind(version)
            .execute(&mut *tx).await.map_err(unavailable)?.rows_affected();
        if changed != 1 {
            return Err(Error::Unauthorized);
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(true)
    }
}
