use super::{ProbeResult, network::Network};
use auth_core::{
    GoogleAuthorization, GoogleCodeExchange, OAuthConnection, OAuthMixupDefense, OAuthTransactions,
    OidcClientAuthentication, OidcClientSecret,
};
use auth_postgres::Postgres;
use easy_auth_server::GoogleDesktopListener;
use sqlx::PgPool;
use std::{net::Ipv4Addr, sync::Arc};
use uuid::Uuid;

pub(super) const ISSUER: &str = "https://accounts.google.com";

pub(super) struct Setup {
    pub store: Arc<Postgres>,
    pub configuration: OAuthConnection,
    pub listener: GoogleDesktopListener,
    pub network: Arc<Network>,
}

impl Setup {
    pub async fn new(pool: &PgPool) -> ProbeResult<Self> {
        let store = Arc::new(Postgres::new(pool.clone()));
        store
            .migrate()
            .await
            .map_err(|_| "owned_database_migration")?;
        let realm = Uuid::new_v4();
        store.ensure_realm(realm).await.map_err(|_| "owned_realm")?;
        let listener =
            GoogleDesktopListener::bind(Ipv4Addr::LOCALHOST.into(), "/provider-preflight")
                .await
                .map_err(|_| "owned_listener")?;
        let configuration = OAuthConnection::with_redirect(
            realm,
            Uuid::new_v4(),
            Uuid::new_v4(),
            ISSUER,
            "preflight-placeholder-not-registered",
            listener.redirect().clone(),
            OAuthMixupDefense::RequireIssuer,
        )
        .and_then(OAuthConnection::with_desktop_loopback_returns)
        .map_err(|_| "source_configuration")?;
        let configuration = store
            .configure_oauth_connection(&configuration)
            .await
            .map_err(|_| "source_registration")?;
        Ok(Self {
            store,
            configuration,
            listener,
            network: Arc::new(Network::default()),
        })
    }

    pub fn authorization(&self) -> ProbeResult<GoogleAuthorization> {
        // Placeholder credentials never leave memory. This tool cannot submit token requests.
        let secret = OidcClientSecret::parse("preflight-placeholder-not-registered".to_owned())
            .map_err(|_| "placeholder_configuration")?;
        let exchange = Arc::new(
            GoogleCodeExchange::new(
                self.configuration.clone(),
                self.store.clone(),
                self.store.clone(),
                OidcClientAuthentication::ClientSecretPost(secret),
                self.network.clone(),
                self.network.clone(),
            )
            .map_err(|_| "google_configuration")?,
        );
        let transactions = Arc::new(
            OAuthTransactions::for_desktop_return(
                self.configuration.clone(),
                self.store.clone(),
                self.listener.redirect().clone(),
            )
            .map_err(|_| "operation_configuration")?,
        );
        GoogleAuthorization::new(transactions, exchange).map_err(|_| "google_composition")
    }
}
