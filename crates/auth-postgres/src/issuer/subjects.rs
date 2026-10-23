use super::configuration;
use crate::{Postgres, unavailable};
use auth_core::{Error, IssuerClientRegistration, Result};
use sqlx::{Postgres as Pg, Transaction};
use uuid::Uuid;

impl Postgres {
    /// Trusted metadata allocation only, not proof of consent or an authenticated
    /// owner. Future issuance must separately authorize the actual session/request.
    /// Never expose the local user ID itself as an outbound subject.
    pub async fn issuer_subject(
        &self,
        client: &IssuerClientRegistration,
        user: Uuid,
    ) -> Result<Uuid> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        configuration::lock(&mut tx, client, true).await?;
        let subject = allocate_for_locked_client(&mut tx, client, user).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(subject)
    }
}

/// Caller holds this exact enabled client configuration before any owner lock.
/// Keep allocation inside the caller's transaction so a later code/audit failure
/// also rolls back a newly assigned subject. No consent/session policy lives here.
pub(super) async fn allocate_for_locked_client(
    tx: &mut Transaction<'_, Pg>,
    client: &IssuerClientRegistration,
    user: Uuid,
) -> Result<Uuid> {
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR KEY SHARE")
            .bind(client.realm())
            .bind(user)
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?;
    if owner.is_none() {
        return Err(Error::Unauthorized);
    }
    sqlx::query("INSERT INTO auth_issuer_subjects(realm_id,sector,user_id,subject) VALUES ($1,$2,$3,$4) ON CONFLICT (realm_id,sector,user_id) DO NOTHING")
            .bind(client.realm()).bind(client.sector()).bind(user).bind(Uuid::new_v4())
            .execute(&mut **tx).await.map_err(unavailable)?;
    let subject = sqlx::query_scalar(
        "SELECT subject FROM auth_issuer_subjects WHERE realm_id=$1 AND sector=$2 AND user_id=$3",
    )
    .bind(client.realm())
    .bind(client.sector())
    .bind(user)
    .fetch_one(&mut **tx)
    .await
    .map_err(unavailable)?;
    Ok(subject)
}
