use super::setup::*;
use crate::support::Mail;
use auth_postgres::Postgres;
use easy_auth_axum::{AppleWebServices, BrowserConfig, experimental_apple_web_router};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn create(pool: PgPool, origin: &str) -> Fixture {
    compose(pool, origin, Custody::Discard).await
}
#[cfg(feature = "apple-grants-web")]
pub(super) async fn with_grants(
    pool: PgPool,
    origin: &str,
    vault: Option<Arc<AppleGrantVault>>,
) -> Fixture {
    compose(pool, origin, Custody::Capture(vault)).await
}
enum Custody {
    Discard,
    #[cfg(feature = "apple-grants-web")]
    Capture(Option<Arc<AppleGrantVault>>),
}
async fn compose(pool: PgPool, origin: &str, custody: Custody) -> Fixture {
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
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&pool)
            .await
            .unwrap();
    let (provider, signer) = Provider::new(now as u64);
    let config = OAuthConnection::new(
        realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        ISSUER,
        CLIENT,
        &format!("{origin}/apple/callback"),
        OAuthMixupDefense::DedicatedRedirect,
    )
    .unwrap();
    let policy = store
        .configure_oidc_identity_policy(
            &OidcIdentityPolicy::new(config, &[ISSUER], OidcDisplayNameClaim::Subject)
                .unwrap()
                .with_jit(OidcJitPolicy::Allow),
        )
        .await
        .unwrap();
    let exchange = Arc::new(
        AppleCodeExchange::new(
            policy.configuration().clone(),
            store.clone(),
            store.clone(),
            signer,
            AppleClientType::Web,
            provider.clone(),
            provider.clone(),
        )
        .unwrap(),
    );
    let transactions = Arc::new(OAuthTransactions::new(
        policy.configuration().clone(),
        store.clone(),
    ));
    let services = match custody {
        Custody::Discard => AppleWebServices::new(
            policy.clone(),
            transactions,
            exchange,
            Arc::new(OidcSignIn::new(store.clone())),
        ),
        #[cfg(feature = "apple-grants-web")]
        Custody::Capture(_) => AppleWebServices::new_with_grants(
            policy.clone(),
            transactions,
            exchange,
            Arc::new(AppleGrantSignIn::new(store.clone())),
        ),
    }
    .unwrap();
    let auth = Auth::new(realm, store.clone(), Arc::new(Mail::default()));
    let app = experimental_apple_web_router(
        auth.clone(),
        BrowserConfig::new(origin, false).unwrap(),
        services.clone(),
    )
    .unwrap();
    Fixture {
        app,
        pool,
        store,
        provider,
        policy,
        auth,
        services,
    }
}
