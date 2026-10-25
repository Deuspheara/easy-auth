use super::{FixtureResult, mail::Mail, send};
use auth_core::{
    Auth, IssuerAuthority, IssuerAuthorization, IssuerClientRegistration, IssuerPkceVerifier,
    Secret,
};
use auth_postgres::Postgres;
use axum::{Json, Router, routing::get};
use easy_auth_axum::{BrowserConfig, experimental_issuer_consent_router};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub(super) async fn run(pool: &PgPool, origin: String) -> FixtureResult<()> {
    let store = Arc::new(Postgres::new(pool.clone()));
    store.migrate().await?;
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await?;
    let client = store
        .configure_issuer_client(&IssuerClientRegistration::public(
            realm,
            Uuid::new_v4(),
            &["https://client.example/callback"],
        )?)
        .await?;
    let pkce = IssuerPkceVerifier::parse(Secret::generate()?.expose().to_owned())?;
    let public = serde_json::json!({"client_id":client.client(),"challenge":pkce.challenge()});
    let mail = Arc::new(Mail::default());
    let inbox = mail.clone();
    let app = experimental_issuer_consent_router(
        Auth::new(realm, store.clone(), mail),
        BrowserConfig::new(&origin, false)?,
        Arc::new(IssuerAuthorization::new(
            IssuerAuthority::new(realm, &origin)?,
            store,
        )),
    )?;
    // This disposable private fixture models actual EmailDelivery. It neither
    // constructs a session nor bypasses browser-bound email proof consumption.
    let fixture =
        Router::new()
            .route(
                "/fixture/issuer/public",
                get(move || {
                    let value = public.clone();
                    async move { Json(value) }
                }),
            )
            .route(
                "/fixture/mail",
                get(move || {
                    let inbox = inbox.clone();
                    async move {
                        Json(serde_json::json!({"token":inbox.sign_ins.lock().unwrap().pop()}))
                    }
                }),
            );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    send(serde_json::json!({"address":listener.local_addr()?.to_string()}))?;
    axum::serve(listener, app.merge(fixture))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    let facts:(i64,i64,i64,i64,i64)=tokio::time::timeout(Duration::from_secs(5),sqlx::query_as(
        "SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_subjects WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_authorizations WHERE realm_id=$1 AND status='approved'),(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='issuer_authorized')"
    ).bind(realm).fetch_one(pool)).await??;
    send(
        serde_json::json!({"facts":{"users":facts.0,"sessions":facts.1,"subjects":facts.2,"approved":facts.3,"issuer_audit":facts.4}}),
    )?;
    Ok(())
}
