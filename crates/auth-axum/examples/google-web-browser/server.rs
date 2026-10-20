use super::{
    FixtureResult, authorize,
    mail::DisabledMail,
    provider::{CLIENT, ISSUER, Provider},
    send,
};
use auth_core::*;
use auth_postgres::Postgres;
use axum::{Router, routing::get};
use easy_auth_axum::{BrowserConfig, GoogleWebServices, experimental_google_web_router};
use sqlx::PgPool;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
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
        &format!("{origin}/google/callback"),
        OAuthMixupDefense::RequireIssuer,
    )?;
    let policy = store
        .configure_oidc_identity_policy(
            &OidcIdentityPolicy::new(config, &[ISSUER], OidcDisplayNameClaim::Subject)?
                .with_jit(OidcJitPolicy::Allow),
        )
        .await?;
    let provider = Provider::new();
    let exchange = Arc::new(
        GoogleCodeExchange::new(
            policy.configuration().clone(),
            store.clone(),
            store.clone(),
            provider.authentication(),
            provider.clone(),
            provider.clone(),
        )?
        .with_session_age_claims(),
    );
    let services = GoogleWebServices::new(
        policy.clone(),
        Arc::new(OAuthTransactions::new(
            policy.configuration().clone(),
            store.clone(),
        )),
        exchange,
        Arc::new(OidcSignIn::new(store.clone())),
        Arc::new(OidcAccountDeletion::new(store.clone())),
    )?;
    let app = experimental_google_web_router(
        Auth::new(realm, store, Arc::new(DisabledMail)),
        BrowserConfig::new(&origin, false)?,
        services,
    )?;
    let authorization = Router::new()
        .route("/fixture/google/authorize", get(authorize::response))
        .with_state(authorize::Source {
            pool: pool.clone(),
            configuration: policy.configuration().clone(),
            provider: provider.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    send(serde_json::json!({"address":listener.local_addr()?.to_string()}))?;
    axum::serve(listener, app.merge(authorization))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    // Shutdown is bounded by the owning runner too; this is aggregate observation,
    // not a session/identity setup or a proof imported through a fixture endpoint.
    let facts:(i64,i64,i64,i64,i64)=tokio::time::timeout(Duration::from_secs(5),
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1),(SELECT count(*) FROM auth_oauth_transactions WHERE realm_id=$1)").bind(realm).fetch_one(pool)).await??;
    send(
        serde_json::json!({"facts":{"users":facts.0,"identities":facts.1,"sessions":facts.2,"audit":facts.3,"pending":facts.4,"posts":provider.posts.load(Ordering::SeqCst),"signed":provider.signed.load(Ordering::SeqCst)}}),
    )?;
    Ok(())
}
