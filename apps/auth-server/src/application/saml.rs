//! Composition only: trusted database configuration owns pins and revisions.
use crate::configuration::saml::Prepared;
use auth_axum::{SamlAccountDeletionWebServices, SamlWebServices};
use auth_postgres::Postgres;
use std::sync::Arc;

pub(super) async fn services(
    repository: Arc<Postgres>,
    prepared: Prepared,
) -> Result<SamlWebServices, Box<dyn std::error::Error>> {
    // Defense in depth: no direct caller can mount this provider before approval.
    prepared.authorize_activation()?;
    let policy = repository
        .load_saml_identity_policy(&prepared.policy)
        .await?;
    let deletion = SamlAccountDeletionWebServices::new(
        policy.clone(),
        repository.clone(),
        repository.clone(),
        repository.clone(),
    )?;
    Ok(
        SamlWebServices::new(policy, repository.clone(), repository.clone(), repository)?
            .with_account_deletion(deletion)?,
    )
}
