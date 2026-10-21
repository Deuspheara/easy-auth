//! Owned actual-Keycloak SAML browser/PostgreSQL acceptance. Never deploy.
mod application;
mod configuration;
#[path = "../../../../apps/auth-server/examples/oidc-keycloak/database.rs"]
mod database;
#[path = "../../../../apps/auth-server/examples/oidc-keycloak/ipc.rs"]
mod ipc;
#[path = "../passkey-browser/mail.rs"]
mod mail;
mod observations;
mod owner;

use configuration::{Command, Setup};
use ipc::{read_command, send};
type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("Owned Keycloak SAML fixture failed");
        std::process::exit(1);
    }
}
async fn run() -> FixtureResult<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|v| v == "--remove-owned-database") {
        return database::remove_owned(args.get(1).ok_or("owned database required")?).await;
    }
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let setup: Setup =
        serde_json::from_value(read_command(&mut input)?.ok_or("private setup required")?)?;
    let name = format!("easy_auth_oidc_{}", uuid::Uuid::new_v4().simple());
    let db = database::Database::new(&name).await?;
    let result = async {
        send(serde_json::json!({"database":name}))?;
        let (mut owner, address) = owner::Owner::new(db.pool.clone(), setup).await?;
        let result = async {
            send(serde_json::json!({"ready":true,"address":address}))?;
            while let Some(value) = read_command(&mut input)? {
                let command: Command = serde_json::from_value(value)?;
                let id = match command {
                    Command::Configure {
                        id,
                        realm,
                        certificates,
                        jit,
                    } => {
                        owner.configure(realm, &certificates, jit).await?;
                        id
                    }
                    Command::Select { id, realm } => {
                        owner.select(realm).await?;
                        id
                    }
                    Command::Disable { id } => {
                        owner.disable().await?;
                        id
                    }
                    Command::Facts { id } => {
                        send(serde_json::json!({"id":id,"facts":owner.facts().await?}))?;
                        continue;
                    }
                    Command::Close => break,
                };
                send(serde_json::json!({"id":id,"configured":true}))?;
            }
            send(serde_json::json!({"facts":owner.facts().await?}))?;
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        owner.close().await?;
        result
    }
    .await;
    db.close().await?;
    send(serde_json::json!({"fixture_database_removed":true}))?;
    result
}
