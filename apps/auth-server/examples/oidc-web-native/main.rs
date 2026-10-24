//! Owned configured-application acceptance. Private TLS/IPC only; never deploy.
#[path = "../../src/application.rs"]
mod application;
#[path = "../../src/oidc_http/cache_headers.rs"]
mod cache_headers;
#[path = "../../src/oidc_http/client.rs"]
mod client;
#[path = "../../src/configuration.rs"]
mod configuration;
#[path = "../oidc-keycloak/database.rs"]
mod database;
#[path = "../embedded/application.rs"]
mod embedded;
#[path = "../oidc-keycloak/ipc.rs"]
mod ipc;
mod observation;
mod owner;
#[path = "../../src/oidc_http/post.rs"]
mod post;
#[path = "../../src/oidc_http/response.rs"]
mod response;
mod server;
#[path = "../../src/smtp.rs"]
mod smtp;
mod transport;
#[path = "../oidc-keycloak/transport.rs"]
mod transport_port;

#[cfg(feature = "issuer-web")]
use easy_auth_server::load_issuer_signing_key;
use ipc::{read_command, send};
use transport::OwnedHttps as OidcHttps;
type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("Owned OIDC web fixture failed");
        std::process::exit(1);
    }
}
async fn run() -> FixtureResult<()> {
    let mut input = std::io::stdin().lock();
    match std::env::args().nth(1).as_deref() {
        Some("--remove-owned-database") => {
            database::remove_owned(&std::env::args().nth(2).ok_or("missing owned database")?).await
        }
        Some("--database-owner") => owner::run(&mut input).await,
        None => server::run(&mut input).await,
        _ => Err("unsupported fixture role".into()),
    }
}
