use super::database;
use sqlx::postgres::PgPoolOptions;
use std::{error::Error, process::Command, time::Duration};
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

pub(super) async fn run(server_flag: &str) -> Result<(), Box<dyn Error>> {
    let mut url = Url::parse(&std::env::var("DATABASE_URL")?)?;
    database::require_loopback(&url)?;
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(url.as_str())
        .await?;
    let name = format!("easy_auth_smtp_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&admin)
        .await?;
    url.set_path(&name);
    let result = run_child(url.as_str(), server_flag).await;
    // The child is stopped before collecting facts or dropping this owned DB.
    let facts = database::facts(url.as_str()).await;
    let dropped = sqlx::query(&format!("DROP DATABASE \"{name}\""))
        .execute(&admin)
        .await;
    admin.close().await;
    dropped?;
    println!("{}", serde_json::json!({"fixture_database_removed":true}));
    result?;
    println!("{}", facts?);
    Ok(())
}

async fn run_child(database_url: &str, server_flag: &str) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    // configured_auth reads a trusted public origin. Release the temporary port
    // before launching the child; any bind collision fails closed, never retries
    // against an unrelated listener or changes origin after configuration.
    drop(listener);
    let mut child = Command::new(std::env::current_exe()?)
        .arg(server_flag)
        .env("DATABASE_URL", database_url)
        .env("AUTH_DEVELOPMENT", "true")
        .env("AUTH_REALM_ID", Uuid::new_v4().to_string())
        .env("AUTH_PUBLIC_URL", format!("http://localhost:{port}"))
        .env("AUTH_BIND", format!("127.0.0.1:{port}"))
        .env("SMTP_HOST", "127.0.0.1")
        .env_remove("SMTP_USERNAME")
        .env_remove("SMTP_PASSWORD")
        .env_remove("AUTH_PASSWORD_BLOCKLIST_FILE")
        .spawn()?;
    let interrupted = tokio::signal::ctrl_c();
    tokio::pin!(interrupted);
    loop {
        tokio::select! {
            result = &mut interrupted => {
                // No in-process fixture API or state mutation. Stopping the
                // process closes its pools before the parent drops the DB.
                let killed = child.kill();
                let waited = child.wait();
                result?;
                killed?;
                waited?;
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if child.try_wait()?.is_some() {
                    return Err("fixture server stopped unexpectedly".into());
                }
            }
        }
    }
}
