use crate::{Postgres, unavailable};
use auth_core::{AppleGrantBinding, AppleGrantCapture, Error, Result};
use sqlx::Transaction;
use uuid::Uuid;

pub(in crate::oauth::identities) async fn insert(
    store: &Postgres,
    tx: &mut Transaction<'_, sqlx::Postgres>,
    identity: Uuid,
    capture: AppleGrantCapture,
) -> Result<()> {
    let vault = store.apple_grant_vault.as_ref().ok_or(Error::Unavailable)?;
    let c = capture.configuration().clone();
    let id = Uuid::new_v4();
    let binding = AppleGrantBinding::new(c.realm(), c.connection(), c.client(), identity, id)?;
    let envelope = capture.seal(binding, vault).await?;
    // The identity is the one actually resolved/inserted while holding the
    // existing source/subject/owner locks. Only authenticated ciphertext enters SQL.
    sqlx::query("INSERT INTO auth_apple_grants(realm_id,id,connection_id,client_id,provider_client,identity_id,binding_identity_id,key_id,ciphertext) VALUES($1,$2,$3,$4,$5,$6,$6,$7,$8)")
        .bind(c.realm()).bind(id).bind(c.connection()).bind(c.client()).bind(c.provider_client())
        .bind(identity).bind(envelope.key_id()).bind(envelope.ciphertext())
        .execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}
