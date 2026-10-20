use crate::{OidcHttps, configuration::oidc::Prepared};
use auth_axum::{BrowserConfig, OidcWebServices, oidc_web_router};
use auth_core::{
    Auth, OAuthTransactions, OidcAccountDeletion, OidcCodeExchange, OidcDocuments, OidcSignIn,
};
use auth_postgres::Postgres;
use axum::Router;
use std::sync::Arc;

pub(super) async fn router(
    auth: Auth,
    browser: BrowserConfig,
    repository: Arc<Postgres>,
    prepared: Prepared,
) -> Result<Router, Box<dyn std::error::Error>> {
    // Only unchanged loading or genuinely absent initial provisioning; explicit
    // administrative reconfiguration owns rotation/cancellation and re-enabling.
    let policy = repository
        .load_or_initialize_oidc_identity_policy(&prepared.policy)
        .await?;
    let http = Arc::new(OidcHttps::new());
    let origins: Vec<_> = prepared.origins.iter().map(String::as_str).collect();
    let documents = Arc::new(OidcDocuments::new(
        policy.configuration().clone(),
        &origins,
        repository.clone(),
        http.clone(),
    )?);
    let transactions = Arc::new(OAuthTransactions::new(
        policy.configuration().clone(),
        repository.clone(),
    ));
    let exchange = Arc::new(OidcCodeExchange::new(
        documents,
        repository.clone(),
        prepared.verification,
        prepared.authentication,
        http,
    ));
    let services = OidcWebServices::new(
        policy,
        transactions,
        exchange,
        Arc::new(OidcSignIn::new(repository.clone())),
        Arc::new(OidcAccountDeletion::new(repository)),
    )?;
    Ok(oidc_web_router(auth, browser, services)?)
}
