use super::{
    FixtureResult, authorize,
    mail::DisabledMail,
    provider::{CLIENT, ISSUER, Provider},
    send,
};
use auth_core::*;
use auth_postgres::Postgres;
use axum::{Router, routing::get};
use easy_auth_axum::{AppleWebServices, BrowserConfig, experimental_apple_web_router};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub(super) async fn run(pool: &PgPool, origin: String) -> FixtureResult<()> {
    let store = Arc::new(Postgres::new(pool.clone()));
    store.migrate().await?;
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await?;
    let config = OAuthConnection::new(
        realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        ISSUER,
        CLIENT,
        &format!("{origin}/apple/callback"),
        OAuthMixupDefense::DedicatedRedirect,
    )?;
    let policy = store
        .configure_oidc_identity_policy(
            &OidcIdentityPolicy::new(config, &[ISSUER], OidcDisplayNameClaim::Subject)?
                .with_jit(OidcJitPolicy::Allow),
        )
        .await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(pool)
            .await?;
    let (provider, signer) = Provider::new(now as u64);
    let exchange = Arc::new(AppleCodeExchange::new(
        policy.configuration().clone(),
        store.clone(),
        store.clone(),
        signer,
        AppleClientType::Web,
        provider.clone(),
        provider.clone(),
    )?);
    let services = AppleWebServices::new(
        policy.clone(),
        Arc::new(OAuthTransactions::new(
            policy.configuration().clone(),
            store.clone(),
        )),
        exchange,
        Arc::new(OidcSignIn::new(store.clone())),
    )?;
    let app = experimental_apple_web_router(
        Auth::new(realm, store, Arc::new(DisabledMail)),
        BrowserConfig::new(&origin, false)?,
        services,
    )?;
    let source = authorize::Source {
        pool: pool.clone(),
        configuration: policy.configuration().clone(),
        provider,
    };
    let fixtures = Router::new()
        .route("/fixture/apple/authorize", get(authorize::response))
        .route("/fixture/apple/facts", get(authorize::facts))
        .with_state(source.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    send(serde_json::json!({"address":listener.local_addr()?.to_string()}))?;
    axum::serve(listener, app.merge(fixtures))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    let facts = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        authorize::snapshot(&source),
    )
    .await??;
    send(serde_json::json!({"facts":facts}))?;
    Ok(())
}
