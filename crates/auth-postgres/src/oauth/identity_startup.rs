//! Stable trusted startup loading, separate from administrative reconfiguration.
use super::{configuration, identity_policy};
use crate::{Postgres, unavailable};
use auth_core::{Error, OidcIdentityPolicy, Result};
use sqlx::{Postgres as Pg, Transaction};
use uuid::Uuid;

impl Postgres {
    /// Load the complete matching enabled definition without changing its
    /// revision, pending work or sessions. Atomically initialize only an absent
    /// registry key, always with a fresh revision. Never adopt generic OAuth
    /// records, change policy or clear an operator disable. This is trusted
    /// startup composition, not an administrative/browser mutation endpoint.
    pub async fn load_or_initialize_oidc_identity_policy(
        &self,
        input: &OidcIdentityPolicy,
    ) -> Result<OidcIdentityPolicy> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let revision = match configuration::current_revision(&mut tx, input.configuration()).await?
        {
            Some(revision) => revision,
            None => initialize(&mut tx, input).await?,
        };
        // A database snapshot is not authority. Validate the whole immutable
        // definition/policy and enable state under config-before-policy locks.
        let actual = input
            .clone()
            .with_persisted_revision(revision)
            .map_err(|_| Error::Unavailable)?;
        identity_policy::lock(&mut tx, &actual).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(actual)
    }
}

async fn initialize(tx: &mut Transaction<'_, Pg>, input: &OidcIdentityPolicy) -> Result<Uuid> {
    // Ignore even a previously persisted caller revision: removing/recreating a
    // registry entry must not revive an already claimed historical exchange.
    let fresh = input.clone().with_persisted_revision(Uuid::new_v4())?;
    let created = configuration::insert_initial(tx, fresh.configuration()).await?;
    let revision = configuration::current_revision(tx, input.configuration())
        .await?
        .ok_or(Error::Unauthorized)?;
    if created {
        identity_policy::replace(tx, &fresh).await?;
    }
    // A concurrent initializer may have won. Its committed full policy must
    // match in the caller. A generic OAuth row never gets policy attached here.
    Ok(revision)
}
