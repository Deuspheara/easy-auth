use super::{FixtureResult, composition, mail::Mail, send};
use axum::{Json, Router, routing::get};
use sqlx::PgPool;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

pub(super) async fn run(pool: &PgPool, origin: String) -> FixtureResult<()> {
    let mail = Arc::new(Mail::default());
    let application = composition::create(pool, &origin, mail.clone()).await?;
    // Owned private inbox only: real EmailDelivery receives the token, and the
    // normal browser/email/PG path must consume it. No session/proof seeding.
    let fixtures = Router::new().route(
        "/fixture/mail",
        get(move || {
            let inbox = mail.clone();
            async move { Json(serde_json::json!({"token":inbox.sign_ins.lock().unwrap().pop()})) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    send(serde_json::json!({"address":listener.local_addr()?.to_string()}))?;
    axum::serve(listener, application.router.merge(fixtures))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    let facts:(i64,i64,i64,i64,i64)=tokio::time::timeout(Duration::from_secs(5),
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1),(SELECT count(*) FROM auth_oauth_transactions WHERE realm_id=$1)").bind(application.realm).fetch_one(pool)).await??;
    send(
        serde_json::json!({"facts":{"users":facts.0,"identities":facts.1,"sessions":facts.2,"audit":facts.3,"pending":facts.4,
        "google_posts":application.google.posts.load(Ordering::SeqCst),"google_signed":application.google.signed.load(Ordering::SeqCst),
        "apple_posts":application.apple.posts.load(Ordering::SeqCst),"apple_signed":application.apple.signed.load(Ordering::SeqCst)}}),
    )?;
    Ok(())
}
