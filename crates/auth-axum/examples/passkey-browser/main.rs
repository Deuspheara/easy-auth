//! Disposable browser-test fixture only. Never deploy or use as an authentication server.
mod counterless;
mod fixture;
mod mail;

use sqlx::postgres::PgPoolOptions;
use std::error::Error;
use url::Url;
use uuid::Uuid;

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        // Never reflect environment, URLs, session fixtures or protocol payloads.
        eprintln!("passkey browser fixture failed");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let admin_url = std::env::var("DATABASE_URL")?;
    let mut database_url = Url::parse(&admin_url)?;
    if !matches!(
        database_url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    ) {
        return Err("browser fixture requires loopback PostgreSQL".into());
    }
    let sessions: Vec<String> = serde_json::from_str(&std::env::var("EASY_AUTH_TEST_SESSIONS")?)?;
    if sessions.is_empty() || sessions.len() > 32 {
        return Err("invalid fixture count".into());
    }
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&admin_url)
        .await?;
    let name = format!("easy_auth_browser_{}", Uuid::new_v4().simple());
    // Only this generated prefix/UUID enters identifiers. Never drop an input database.
    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&admin)
        .await?;
    database_url.set_path(&name);
    let result = fixture::serve(database_url.as_str(), sessions).await;
    sqlx::query(&format!("DROP DATABASE \"{name}\""))
        .execute(&admin)
        .await?;
    println!("{}", serde_json::json!({"fixture_database_removed":true}));
    result
}
