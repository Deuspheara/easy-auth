use super::{
    ProbeResult,
    settings::{ClaimsProfile, Settings},
};
use auth_core::{
    GoogleAuthorization, GoogleCodeExchange, OAuthConnection, OAuthMixupDefense, OAuthTransactions,
    OidcDisplayNameClaim, OidcHttp, OidcIdentityPolicy, OidcJitPolicy, OidcTokenHttp,
};
use auth_postgres::Postgres;
use easy_auth_server::GoogleDesktopListener;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub(super) struct Setup {
    pub store: Arc<Postgres>,
    pub policy: OidcIdentityPolicy,
    pub listener: GoogleDesktopListener,
    pub service: Arc<GoogleAuthorization>,
}
impl Setup {
    pub async fn new(
        pool: &PgPool,
        settings: Settings,
        http: Arc<dyn OidcHttp>,
        tokens: Arc<dyn OidcTokenHttp>,
    ) -> ProbeResult<Self> {
        let store = Arc::new(Postgres::new(pool.clone()));
        store
            .migrate()
            .await
            .map_err(|_| "owned_database_migration")?;
        let listener = GoogleDesktopListener::bind(settings.ip, "/google-native-acceptance")
            .await
            .map_err(|_| "owned_listener")?;
        let policy = source(&store, &settings.client, &listener).await?;
        let service = authorization(&store, &policy, &listener, settings, http, tokens)?;
        Ok(Self {
            store,
            policy,
            listener,
            service: Arc::new(service),
        })
    }
}

async fn source(
    store: &Arc<Postgres>,
    client: &str,
    listener: &GoogleDesktopListener,
) -> ProbeResult<OidcIdentityPolicy> {
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.map_err(|_| "owned_realm")?;
    let configuration = OAuthConnection::with_redirect(
        realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "https://accounts.google.com",
        client,
        listener.redirect().clone(),
        OAuthMixupDefense::RequireIssuer,
    )
    .and_then(OAuthConnection::with_desktop_loopback_returns)
    .map_err(|_| "google_configuration")?;
    let input = OidcIdentityPolicy::new(
        configuration,
        &["https://accounts.google.com"],
        OidcDisplayNameClaim::Subject,
    )
    .map_err(|_| "identity_configuration")?
    .with_jit(OidcJitPolicy::Allow);
    store
        .load_or_initialize_oidc_identity_policy(&input)
        .await
        .map_err(|_| "source_registration")
}

fn authorization(
    store: &Arc<Postgres>,
    policy: &OidcIdentityPolicy,
    listener: &GoogleDesktopListener,
    settings: Settings,
    http: Arc<dyn OidcHttp>,
    tokens: Arc<dyn OidcTokenHttp>,
) -> ProbeResult<GoogleAuthorization> {
    let Settings {
        authentication,
        profile,
        ..
    } = settings;
    let configuration = policy.configuration().clone();
    let transactions = Arc::new(
        OAuthTransactions::for_desktop_return(
            configuration.clone(),
            store.clone(),
            listener.redirect().clone(),
        )
        .map_err(|_| "operation_configuration")?,
    );
    let exchange = GoogleCodeExchange::new(
        configuration,
        store.clone(),
        store.clone(),
        authentication,
        http,
        tokens,
    )
    .map_err(|_| "google_configuration")?;
    match profile {
        ClaimsProfile::Base => GoogleAuthorization::new(transactions, Arc::new(exchange)),
        ClaimsProfile::SessionAge => GoogleAuthorization::new_session_age(
            transactions,
            Arc::new(exchange.with_session_age_claims()),
        ),
    }
    .map_err(|_| "google_composition")
}
