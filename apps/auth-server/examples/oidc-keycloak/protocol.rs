use super::{FixtureResult, send, transport::Http};
use auth_core::*;
use auth_postgres::Postgres;
use serde_json::json;
use std::sync::Arc;

pub(super) fn exchange(
    connection: &OAuthConnection,
    store: Arc<Postgres>,
    http: Arc<Http>,
    secret: String,
) -> FixtureResult<OidcCodeExchange> {
    let origin = url::Url::parse(connection.issuer())?
        .origin()
        .ascii_serialization();
    send(json!({"phase":"document_configuration"}))?;
    let documents = Arc::new(OidcDocuments::new(
        connection.clone(),
        &[&origin],
        store.clone(),
        http.clone(),
    )?);
    send(json!({"phase":"exchange_configuration"}))?;
    Ok(OidcCodeExchange::new(
        documents,
        store,
        OidcVerificationPolicy::new(&[OidcSigningAlgorithm::RS256], &[])?,
        OidcClientAuthentication::ClientSecretBasic(OidcClientSecret::parse(secret)?),
        http,
    ))
}
