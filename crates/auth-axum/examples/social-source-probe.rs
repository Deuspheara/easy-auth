//! Private owned-fixture check. Reads a real session over stdin; never deploy.
#[path = "passkey-browser/mail.rs"]
mod mail;
use auth_core::{Auth, Error, Secret};
use auth_postgres::Postgres;
use serde::Deserialize;
use std::{io::Read, sync::Arc};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    realm: Uuid,
    session: String,
}
#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("Owned source probe failed");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let input: Input = serde_json::from_reader(std::io::stdin().lock().take(4096))?;
    let session = Secret::parse(input.session)?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL")?)
        .await?;
    let auth = Auth::new(
        input.realm,
        Arc::new(Postgres::new(pool.clone())),
        Arc::new(mail::DisabledMail),
    );
    let authenticated = match auth.authenticate(&session).await {
        Ok(_) => true,
        Err(Error::Unauthorized) => false,
        Err(_) => return Err("owned authentication check unavailable".into()),
    };
    println!(
        "{}",
        serde_json::json!({"authenticated":authenticated,
        "linking_selected":cfg!(feature="social-linking-web")})
    );
    pool.close().await;
    Ok(())
}
