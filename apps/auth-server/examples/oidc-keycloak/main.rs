//! Owned provider acceptance fixture. Never deploy or attach its private IPC to a log.
#[path = "../../src/oidc_http/cache_headers.rs"]
mod cache_headers;
#[path = "../../src/oidc_http/client.rs"]
mod client;
mod database;
mod fixture;
#[cfg(feature = "oidc-identities")]
mod identities;
#[path = "../../src/oidc_http/post.rs"]
mod post;
mod protocol;
#[path = "../../src/oidc_http/response.rs"]
mod response;
mod transactions;
mod transport;

use std::io::{BufRead, Write};

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

fn read_command(input: &mut impl BufRead) -> FixtureResult<Option<serde_json::Value>> {
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    if line.len() > 65536 {
        return Err("fixture IPC bound exceeded".into());
    }
    Ok(Some(serde_json::from_str(&line)?))
}
fn send(value: serde_json::Value) -> FixtureResult<()> {
    // stdout is a private pipe owned by the runner, never a user-facing log.
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}
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
