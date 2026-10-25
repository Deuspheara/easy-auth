use super::{FixtureResult, apple, apple_provider, google, google_provider, mail::Mail};
use auth_core::*;
use auth_postgres::Postgres;
use axum::Router;
use easy_auth_axum::{AppleWebServices, BrowserConfig, GoogleWebServices, SocialWebServices};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub(super) struct Application {
    pub router: Router,
    pub realm: Uuid,
    pub google: Arc<google_provider::Provider>,
    pub apple: Arc<apple_provider::Provider>,
    #[cfg(feature = "apple-grants-web")]
    pub custody: Option<Arc<super::grants::Fixture>>,
}
pub(super) async fn create(
    pool: &PgPool,
    origin: &str,
    mail: Arc<Mail>,
    capture: bool,
) -> FixtureResult<Application> {
    #[cfg(not(feature = "apple-grants-web"))]
    if capture {
        return Err("capture fixture not compiled".into());
    }
    let store = Postgres::new(pool.clone());
    #[cfg(feature = "apple-grants-web")]
    let vault = if capture {
        Some(super::grants::vault()?)
    } else {
        None
    };
    #[cfg(feature = "apple-grants-web")]
    let store = match &vault {
        Some(vault) => store.with_apple_grant_vault(vault.clone()),
        None => store,
    };
    let store = Arc::new(store);
    store.migrate().await?;
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await?;
    let configure = |issuer: &str, client: &str, path: &str, mixup| -> auth_core::Result<_> {
        Ok(OidcIdentityPolicy::new(
            OAuthConnection::new(
                realm,
                Uuid::new_v4(),
                Uuid::new_v4(),
                issuer,
                client,
                &format!("{origin}/{path}/callback"),
                mixup,
            )?,
            &[issuer],
            OidcDisplayNameClaim::Subject,
        )?
        .with_jit(OidcJitPolicy::Allow))
    };
    let google_policy = store
        .configure_oidc_identity_policy(&configure(
            google_provider::ISSUER,
            google_provider::CLIENT,
            "google",
            OAuthMixupDefense::RequireIssuer,
        )?)
        .await?;
    let apple_policy = store
        .configure_oidc_identity_policy(&configure(
            apple_provider::ISSUER,
            apple_provider::CLIENT,
            "apple",
            OAuthMixupDefense::DedicatedRedirect,
        )?)
        .await?;
    let google = google_provider::Provider::new();
    let google_exchange = Arc::new(
        GoogleCodeExchange::new(
            google_policy.configuration().clone(),
            store.clone(),
            store.clone(),
            google.authentication(),
            google.clone(),
            google.clone(),
        )?
        .with_session_age_claims(),
    );
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(pool)
            .await?;
    let (apple, signer) = apple_provider::Provider::new(now as u64);
    let signer = Arc::new(signer);
    let apple_exchange = Arc::new(AppleCodeExchange::with_shared_signer(
        apple_policy.configuration().clone(),
        store.clone(),
        store.clone(),
        signer.clone(),
        AppleClientType::Web,
        apple.clone(),
        apple.clone(),
    )?);
    let google_transactions = Arc::new(OAuthTransactions::new(
        google_policy.configuration().clone(),
        store.clone(),
    ));
    let apple_transactions = Arc::new(OAuthTransactions::new(
        apple_policy.configuration().clone(),
        store.clone(),
    ));
    let sign_in = Arc::new(OidcSignIn::new(store.clone()));
    let google_services = GoogleWebServices::new(
        google_policy.clone(),
        google_transactions.clone(),
        google_exchange.clone(),
        sign_in.clone(),
        Arc::new(OidcAccountDeletion::new(store.clone())),
    )?;
    #[cfg(feature = "apple-grants-web")]
    let custody = vault
        .map(|vault| {
            super::grants::Fixture::new(
                pool.clone(),
                realm,
                apple_policy.configuration().clone(),
                signer,
                vault,
                store.clone(),
                apple.clone(),
            )
        })
        .transpose()?;
    let google_link = Arc::new(GoogleIdentityLinkAuthorization::new_session_age(
        google_transactions,
        google_exchange,
    )?);
    let linking = Arc::new(OidcIdentityLinking::new(store.clone()));
    #[cfg(feature = "apple-grants-web")]
    let selected = if capture {
        let apple_services = AppleWebServices::new_with_grants(
            apple_policy.clone(),
            apple_transactions.clone(),
            apple_exchange.clone(),
            Arc::new(AppleGrantSignIn::new(store.clone())),
        )?;
        Some(SocialWebServices::new_with_apple_grants(
            google_services.clone(),
            apple_services,
            google_link.clone(),
            apple_transactions.clone(),
            apple_exchange.clone(),
            Arc::new(AppleGrantLinking::new(store.clone())),
            linking.clone(),
        )?)
    } else {
        None
    };
    #[cfg(not(feature = "apple-grants-web"))]
    let selected: Option<SocialWebServices> = None;
    let services = match selected {
        Some(services) => services,
        None => SocialWebServices::new(
            google_services,
            AppleWebServices::new(
                apple_policy.clone(),
                apple_transactions.clone(),
                apple_exchange.clone(),
                sign_in,
            )?,
            google_link,
            Arc::new(AppleIdentityLinkAuthorization::new(
                apple_transactions,
                apple_exchange,
            )?),
            linking,
        )?,
    };
    let app = easy_auth_axum::experimental_social_web_router(
        Auth::new(realm, store, mail),
        BrowserConfig::new(origin, false)?,
        services,
    )?;
    let router = app
        .merge(google::routes(
            pool,
            google_policy.configuration(),
            google.clone(),
        ))
        .merge(apple::routes(
            pool,
            apple_policy.configuration(),
            apple.clone(),
        ));
    Ok(Application {
        router,
        realm,
        google,
        apple,
        #[cfg(feature = "apple-grants-web")]
        custody,
    })
}
