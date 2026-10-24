//! Shared embedded/standalone composition; no provisioning or enable writes.
use crate::configuration::issuer::Prepared;
use auth_axum::{IssuerNativeWebServices, IssuerWebServices};
use auth_postgres::Postgres;
use std::sync::Arc;

pub(super) async fn services(
    repository: Arc<Postgres>,
    prepared: Prepared,
) -> Result<IssuerNativeWebServices, Box<dyn std::error::Error>> {
    let current = repository
        .load_issuer_signing(&prepared.authority)
        .await
        .map_err(|_| "issuer requires an enabled current persisted signing key")?;
    if current.publication().key()
        != &prepared
            .key
            .public_key()
            .map_err(|_| "issuer signing key input is unavailable or invalid")?
    {
        return Err("issuer signing key does not match the current persisted public key".into());
    }
    let base = IssuerWebServices::new(
        prepared.authority,
        repository.clone(),
        repository.clone(),
        vec![prepared.key],
    )
    .map_err(|_| "issuer service configuration is invalid")?;
    let services = IssuerNativeWebServices::new(
        base,
        repository.clone(),
        repository.clone(),
        repository.clone(),
    );
    Ok(if prepared.introspection {
        services.with_native_introspection(repository)
    } else {
        services
    })
}

#[cfg(test)]
#[path = "issuer/tests.rs"]
mod tests;
