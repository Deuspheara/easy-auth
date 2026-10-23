use super::configuration;
use crate::{Postgres, unavailable};
use auth_core::{Error, IssuerClientAuthentication, IssuerClientRegistration, Result};
use sqlx::{Postgres as Pg, Transaction};

impl Postgres {
    /// Validate request credentials against the current exact enabled definition.
    /// Public identification is not authentication. This grants no code, consent,
    /// token or session; eventual redemption must check inside its own transaction.
    pub async fn validate_issuer_client_authentication(
        &self,
        client: &IssuerClientRegistration,
        authentication: &IssuerClientAuthentication,
    ) -> Result<()> {
        authentication.validate_for(client)?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        validate_current(&mut tx, client, authentication).await?;
        tx.commit().await.map_err(unavailable)
    }
}

/// Acquire the exact enabled client lock before credentials are compared; the
/// caller retains that lock through the complete operation. Call before owners.
/// Credential verifiers use the same database comparison as other opaque secrets;
/// neither a raw credential nor an authenticated-client proof is persisted.
pub(super) async fn validate_current(
    tx: &mut Transaction<'_, Pg>,
    client: &IssuerClientRegistration,
    authentication: &IssuerClientAuthentication,
) -> Result<()> {
    authentication.validate_for(client)?;
    configuration::lock(tx, client, true).await?;
    let accepted: Option<bool> = sqlx::query_scalar(
        "SELECT secret_verifier IS NOT DISTINCT FROM $3 FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2",
    )
    .bind(client.realm())
    .bind(client.client())
    .bind(authentication.secret_verifier().map(|v| v.to_vec()))
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?;
    if accepted != Some(true) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
