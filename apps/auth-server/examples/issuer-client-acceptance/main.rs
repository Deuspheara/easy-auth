//! Disposable real-HTTP acceptance. Private IPC is never a user-facing log.
#[path = "../../src/oidc_http/cache_headers.rs"]
mod cache_headers;
#[path = "../../src/oidc_http/client.rs"]
mod client;
#[path = "../oidc-keycloak/database.rs"]
mod database;
#[path = "../oidc-keycloak/ipc.rs"]
mod ipc;
mod operations;
#[path = "../../src/oidc_http/post.rs"]
mod post;
mod provision;
#[path = "../../src/oidc_http/response.rs"]
mod response;
mod server;
mod session;
#[path = "../oidc-keycloak/transport.rs"]
mod transport;
use ipc::{read_command, send};
type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;
#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("Owned standalone issuer acceptance failed");
        std::process::exit(1);
    }
}
async fn run() -> FixtureResult<()> {
    let argument = std::env::args().nth(1);
    if argument.as_deref() == Some("--embedded") {
        return server::embedded().await;
    }
    if argument.as_deref() == Some("--remove-owned-database") {
        return database::remove_owned(&std::env::args().nth(2).ok_or("owned database required")?)
            .await;
    }
    let mut input = std::io::stdin().lock();
    let config = read_command(&mut input)?.ok_or("owned configuration required")?;
    let name = config["database_name"]
        .as_str()
        .ok_or("owned database name required")?;
    let database = database::Database::new(name).await?;
    send(serde_json::json!({"database_created":database.name}))?;
    let result = session::run(&config, &database, &mut input).await;
    database.close().await?;
    send(serde_json::json!({"database_removed":true}))?;
    result
}
