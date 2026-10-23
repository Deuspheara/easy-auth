use super::{FixtureResult, mail::Mail, send};
use auth_core::{IssuerAuthority, IssuerKeyPublication, IssuerSigningKey};
use auth_postgres::Postgres;
use axum::{Json, Router, routing::get};
use josekit::{jwk::KeyPair, jws::RS256};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use uuid::Uuid;

pub(super) async fn run(pool: &PgPool, origin: String) -> FixtureResult<()> {
    let store = Arc::new(Postgres::new(pool.clone()));
    store.migrate().await?;
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await?;
    let authority = IssuerAuthority::new(realm, &origin)?;
    // Ordinary ephemeral fixture key only. Production must supply protected
    // operator material; no generation/default/provisioning is added there.
    let pair = RS256.generate_key_pair(2048)?;
    let key = Arc::new(IssuerSigningKey::from_pkcs8_pem(
        Uuid::new_v4(),
        String::from_utf8(pair.to_pem_private_key())?,
    )?);
    let now: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(pool)
            .await?;
    store
        .publish_issuer_key(&IssuerKeyPublication::new(
            authority.clone(),
            key.public_key()?,
            now - 1_000_000,
            now + 3_600_000_000,
            now + 3_900_000_000,
        )?)
        .await?;
    let revision = store.activate_issuer_key(&authority, key.id()).await?;
    store.enable_issuer_signing(&authority, revision).await?;
    let mail = Arc::new(Mail::default());
    let inbox = mail.clone();
    let (app, client_id) =
        super::profile::application(realm, &origin, authority, store, key, mail).await?;
    // Only public client metadata and actual EmailDelivery are exposed by this
    // disposable fixture; no session, code, token or private PKCE constructor.
    let fixture =
        Router::new()
            .route(
                "/fixture/issuer/public",
                get(move || async move { Json(serde_json::json!({"client_id":client_id})) }),
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
    axum::serve(
        listener,
        app.merge(fixture)
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    let facts:(i64,i64,i64,i64,i64,i64)=tokio::time::timeout(Duration::from_secs(5),sqlx::query_as(
        "SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_subjects WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_authorizations WHERE realm_id=$1 AND status='consumed'),(SELECT count(*) FROM auth_issuer_access_tokens WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='issuer_code_redeemed')"
    ).bind(realm).fetch_one(pool)).await??;
    send(
        serde_json::json!({"facts":{"users":facts.0,"sessions":facts.1,"subjects":facts.2,"consumed":facts.3,"access":facts.4,"redeemed_audit":facts.5}}),
    )?;
    Ok(())
}
