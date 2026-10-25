//! Owned HTTPS-browser/code/PostgreSQL fixture only. Never deploy.
#[path = "apple.rs"]
mod apple;
#[path = "../../../../tests/support/apple/provider.rs"]
mod apple_provider;
#[path = "composition.rs"]
mod composition;
#[path = "../../../../apps/auth-server/examples/oidc-keycloak/database.rs"]
mod database;
#[path = "google.rs"]
mod google;
#[path = "../../../../tests/support/google/provider.rs"]
mod google_provider;
#[path = "../../tests/support/mail.rs"]
mod mail;
#[path = "server.rs"]
mod server;

use std::io::Write;
type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

// The parent owns this private pipe. Never forward protocol payloads or errors.
fn send(value: serde_json::Value) -> FixtureResult<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

pub(super) async fn run() -> FixtureResult<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|value| value == "--remove-owned-database")
    {
        return database::remove_owned(arguments.get(1).ok_or("owned database required")?).await;
    }
    let origin = arguments.first().ok_or("owned origin required")?;
    let origin = url::Url::parse(origin)?;
    if origin.scheme() != "https"
        || origin.host_str() != Some("app.example")
        || origin.port().is_none()
    {
        return Err("owned HTTPS origin required".into());
    }
    let name = format!("easy_auth_oidc_{}", uuid::Uuid::new_v4().simple());
    let database = database::Database::new(&name).await?;
    // Once creation succeeds, every preparation/IPC/server error must still pass
    // through owned cleanup, including a parent that closes its output pipe early.
    let result = async {
        send(serde_json::json!({"database":name}))?;
        server::run(&database.pool, origin.origin().ascii_serialization()).await
    }
    .await;
    database.close().await?;
    send(serde_json::json!({"fixture_database_removed":true}))?;
    result
}
