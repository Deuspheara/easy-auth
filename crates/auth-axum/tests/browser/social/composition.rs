use super::setup::{Fixture, ORIGIN};
use crate::{apple_provider, google_provider, support::Mail};
use auth_core::*;
use auth_postgres::Postgres;
use easy_auth_axum::{AppleWebServices, GoogleWebServices, SocialWebServices};
use std::sync::Arc;
use uuid::Uuid;

pub(super) async fn create(pool: sqlx::PgPool) -> Fixture {
    compose(pool, Custody::Discard).await
}
#[cfg(feature = "apple-grants-web")]
pub(super) async fn with_grants(
    pool: sqlx::PgPool,
    vault: Option<Arc<AppleGrantVault>>,
) -> Fixture {
    compose(pool, Custody::Capture(vault)).await
}
enum Custody {
    Discard,
    #[cfg(feature = "apple-grants-web")]
    Capture(Option<Arc<AppleGrantVault>>),
}
async fn compose(pool: sqlx::PgPool, custody: Custody) -> Fixture {
    let store = Postgres::new(pool.clone());
    #[cfg(feature = "apple-grants-web")]
    let store = match &custody {
        Custody::Capture(Some(vault)) => store.with_apple_grant_vault(vault.clone()),
        _ => store,
    };
    let store = Arc::new(store);
    store.migrate().await.unwrap();
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    let configure = |issuer: &str, client: &str, path: &str, mixup| {
        OidcIdentityPolicy::new(
            OAuthConnection::new(
                realm,
                Uuid::new_v4(),
                Uuid::new_v4(),
                issuer,
                client,
                &format!("{ORIGIN}/{path}/callback"),
                mixup,
            )
            .unwrap(),
            &[issuer],
            OidcDisplayNameClaim::Subject,
        )
        .unwrap()
        .with_jit(OidcJitPolicy::Allow)
    };
    let google_policy = store
        .configure_oidc_identity_policy(&configure(
            google_provider::ISSUER,
            google_provider::CLIENT,
            "google",
            OAuthMixupDefense::RequireIssuer,
        ))
        .await
        .unwrap();
    let apple_policy = store
        .configure_oidc_identity_policy(&configure(
            apple_provider::ISSUER,
            apple_provider::CLIENT,
            "apple",
            OAuthMixupDefense::DedicatedRedirect,
        ))
        .await
        .unwrap();
    let google = google_provider::Provider::new();
    let google_exchange = Arc::new(
        GoogleCodeExchange::new(
            google_policy.configuration().clone(),
            store.clone(),
            store.clone(),
            google.authentication(),
            google.clone(),
            google.clone(),
        )
        .unwrap()
        .with_session_age_claims(),
    );
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&pool)
            .await
            .unwrap();
    let (apple, signer) = apple_provider::Provider::new(now as u64);
    let signer = Arc::new(signer);
    let apple_exchange = Arc::new(
        AppleCodeExchange::with_shared_signer(
            apple_policy.configuration().clone(),
            store.clone(),
            store.clone(),
            signer.clone(),
            AppleClientType::Web,
            apple.clone(),
            apple.clone(),
        )
        .unwrap(),
    );
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
    )
    .unwrap();
    let apple_services = match &custody {
        Custody::Discard => AppleWebServices::new(
            apple_policy.clone(),
            apple_transactions.clone(),
            apple_exchange.clone(),
            sign_in,
        ),
        #[cfg(feature = "apple-grants-web")]
        Custody::Capture(_) => AppleWebServices::new_with_grants(
            apple_policy.clone(),
            apple_transactions.clone(),
            apple_exchange.clone(),
            Arc::new(AppleGrantSignIn::new(store.clone())),
        ),
    }
    .unwrap();
    let google_link = Arc::new(
        GoogleIdentityLinkAuthorization::new_session_age(google_transactions, google_exchange)
            .unwrap(),
    );
    let linking = Arc::new(OidcIdentityLinking::new(store.clone()));
    let services = match custody {
        Custody::Discard => SocialWebServices::new(
            google_services.clone(),
            apple_services.clone(),
            google_link,
            Arc::new(
                AppleIdentityLinkAuthorization::new(apple_transactions, apple_exchange).unwrap(),
            ),
            linking,
        ),
        #[cfg(feature = "apple-grants-web")]
        Custody::Capture(_) => SocialWebServices::new_with_apple_grants(
            google_services.clone(),
            apple_services.clone(),
            google_link,
            apple_transactions,
            apple_exchange,
            Arc::new(AppleGrantLinking::new(store.clone())),
            linking,
        ),
    }
    .unwrap();
    let mail = Arc::new(Mail::default());
    let auth = Auth::new(realm, store.clone(), mail.clone());
    let app = easy_auth_axum::experimental_social_web_router(
        auth.clone(),
        easy_auth_axum::BrowserConfig::new(ORIGIN, false).unwrap(),
        services.clone(),
    )
    .unwrap();
    Fixture {
        app,
        pool,
        store,
        google,
        apple,
        google_policy,
        apple_policy,
        mail,
        auth,
        google_services,
        apple_services,
        services,
        #[cfg(feature = "apple-grants-web")]
        apple_signer: signer,
    }
}
