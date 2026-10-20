//! Owned provider acceptance fixture. Never deploy or attach its private IPC to a log.
#[path = "../../src/oidc_http/cache_headers.rs"]
mod cache_headers;
#[path = "../../src/oidc_http/client.rs"]
mod client;
mod database;
mod fixture;
#[cfg(feature = "oidc-identities")]
mod identities;
mod ipc;
#[path = "../../src/oidc_http/post.rs"]
mod post;
mod protocol;
#[path = "../../src/oidc_http/response.rs"]
mod response;
mod transactions;
mod transport;

use ipc::{read_command, send};

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() {
    let result = run().await;
    if result.is_err() {
        eprintln!("Owned OIDC acceptance fixture failed");
        std::process::exit(1);
    }
}
async fn run() -> FixtureResult<()> {
    if std::env::args().nth(1).as_deref() == Some("--remove-owned-database") {
        return database::remove_owned(&std::env::args().nth(2).ok_or("missing owned DB")?).await;
    }
    let mut input = std::io::stdin().lock();
    let config = read_command(&mut input)?.ok_or("missing fixture configuration")?;
    let name = config["database_name"]
        .as_str()
        .ok_or("missing owned DB name")?;
    let database = database::Database::new(name).await?;
    send(serde_json::json!({"database_created":database.name}))?;
    let result = fixture::run(config, &database, &mut input).await;
    database.close().await?;
    send(serde_json::json!({"database_removed":true}))?;
    result
}
