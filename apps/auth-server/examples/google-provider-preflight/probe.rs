use super::{
    ProbeResult,
    setup::{ISSUER, Setup},
};
use auth_core::{Error, OAuthIntent, OAuthPurpose, OidcDiscovery, OidcDocuments, Secret};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::atomic::Ordering;

const ORIGINS: &[&str] = &[
    ISSUER,
    "https://oauth2.googleapis.com",
    "https://www.googleapis.com",
];

pub(super) async fn run(pool: &PgPool) -> ProbeResult<Value> {
    let setup = Setup::new(pool).await?;
    let (documents, discovery) = public_documents(&setup).await?;
    authorization_cycle(&setup, &discovery, pool).await?;
    setup
        .store
        .disable_oauth_connection(
            setup.configuration.realm(),
            setup.configuration.connection(),
            setup.configuration.client(),
        )
        .await
        .map_err(|_| "source_disable")?;
    if !matches!(documents.discovery().await, Err(Error::Unauthorized)) {
        return Err("disabled_source_revalidation");
    }
    let posts = setup.network.blocked_posts.load(Ordering::SeqCst);
    if posts != 0 {
        return Err("unexpected_token_request");
    }
    Ok(
        json!({"status":"passed","scope":"public_metadata_only","registered_client":false,
        "public_root_tls":true,"discovery_contract":true,"public_jwks_envelope":true,
        "native_authorization_prepared":true,"exact_operation_return":true,"pending_cancelled":true,
        "disabled_source_rejected":true,"users":0,"identities":0,"sessions":0,"audits":0,"pending":0,
        "public_get_requests":setup.network.gets.load(Ordering::SeqCst),"blocked_token_requests":posts,
        "browser_launched":false,"signature_verified":false}),
    )
}

async fn public_documents(setup: &Setup) -> ProbeResult<(OidcDocuments, OidcDiscovery)> {
    let documents = OidcDocuments::new(
        setup.configuration.clone(),
        ORIGINS,
        setup.store.clone(),
        setup.network.clone(),
    )
    .map_err(|_| "document_configuration")?;
    let discovery = documents
        .discovery()
        .await
        .map_err(|_| "public_discovery_unavailable")?;
    if discovery.issuer() != ISSUER
        || !discovery.supports_s256()
        || !discovery.supports_response_issuer()
        || !discovery
            .token_authentication_methods()
            .iter()
            .any(|method| method == "client_secret_post")
    {
        return Err("public_discovery_contract");
    }
    let _keys = documents
        .jwks()
        .await
        .map_err(|_| "public_jwks_unavailable")?;
    Ok((documents, discovery))
}

async fn authorization_cycle(
    setup: &Setup,
    discovery: &OidcDiscovery,
    pool: &PgPool,
) -> ProbeResult<()> {
    let service = setup.authorization()?;
    let browser = Secret::generate().map_err(|_| "private_proof")?;
    let intent = OAuthIntent {
        browser: &browser,
        source: "public-provider-preflight",
        purpose: OAuthPurpose::SignIn,
    };
    let start = service
        .begin(&intent)
        .await
        .map_err(|_| "public_authorization_preparation_unavailable")?;
    let url = url::Url::parse(start.authorization_url.expose()).map_err(|_| "authorization_url")?;
    let mut destination = url.clone();
    destination.set_query(None);
    if destination.as_str() != discovery.authorization_endpoint()
        || !url.query_pairs().any(|(name, value)| {
            name == "redirect_uri" && value == setup.listener.redirect().as_str()
        })
    {
        return Err("authorization_return");
    }
    facts(pool, 1).await?;
    service
        .cancel(&intent, &start.transaction.state, &start.transaction.proof)
        .await
        .map_err(|_| "pending_cancellation")?;
    facts(pool, 0).await?;
    Ok(())
}

async fn facts(pool: &PgPool, pending: i64) -> ProbeResult<()> {
    let actual: (i64,i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_oidc_identities),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit),(SELECT count(*) FROM auth_oauth_transactions)")
        .fetch_one(pool).await.map_err(|_| "owned_database_observation")?;
    if actual != (0, 0, 0, 0, pending) {
        return Err("unexpected_authority_facts");
    }
    Ok(())
}
