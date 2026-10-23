//! Owned signed issuer acceptance only. Never deploy this fixture or its inbox.
#[path = "../../../../apps/auth-server/examples/oidc-keycloak/database.rs"]
mod database;
#[path = "../../tests/support/mail.rs"]
mod mail;
mod server;
use std::io::Write;
type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;
fn send(value: serde_json::Value) -> FixtureResult<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}
#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("Owned signed issuer fixture failed");
        std::process::exit(1);
    }
}
async fn run() -> FixtureResult<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|s| s == "--remove-owned-database") {
        return database::remove_owned(args.get(1).ok_or("owned database required")?).await;
    }
    let origin = url::Url::parse(args.first().ok_or("owned origin required")?)?;
    if origin.scheme() != "https"
        || origin.host_str() != Some("app.example")
        || origin.port().is_none()
    {
        return Err("owned HTTPS origin required".into());
    }
    let name = format!("easy_auth_oidc_{}", uuid::Uuid::new_v4().simple());
    let database = database::Database::new(&name).await?;
    let result = async {
        send(serde_json::json!({"database":name}))?;
        server::run(&database.pool, origin.origin().ascii_serialization()).await
    }
    .await;
    database.close().await?;
    send(serde_json::json!({"fixture_database_removed":true}))?;
    result
}
