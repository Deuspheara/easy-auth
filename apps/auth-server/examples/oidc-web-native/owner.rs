mod gate;

use super::{FixtureResult, database::Database, observation::Source, read_command, send};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::io::BufRead;

pub(super) async fn run(input: &mut impl BufRead) -> FixtureResult<()> {
    let config = read_command(input)?.ok_or("missing owned database configuration")?;
    let database = Database::new(
        config["database_name"]
            .as_str()
            .ok_or("owned database name")?,
    )
    .await?;
    send(json!({"database_created":database.name}))?;
    let observer = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(database.pool.connect_options().as_ref().clone())
        .await?;
    let mut source = Source::new(&config)?;
    let result = commands(input, &database, &observer, &mut source).await;
    observer.close().await;
    database.close().await?;
    send(json!({"database_removed":true}))?;
    result
}
async fn commands(
    input: &mut impl BufRead,
    database: &Database,
    observer: &PgPool,
    source: &mut Source,
) -> FixtureResult<()> {
    let mut gate = None;
    send(json!({"ready":true,"database_owner":true}))?;
    while let Some(command) = read_command(input)? {
        if command["command"].as_str() == Some("close") {
            break;
        }
        let value = command_result(&command, database, observer, source, &mut gate).await;
        let mut value = value.unwrap_or_else(|_| json!({"result":"infrastructure_failure"}));
        value["id"] = command["id"].clone();
        send(value)?;
    }
    if let Some(gate) = gate {
        gate.release().await?;
    }
    Ok(())
}
async fn command_result(
    command: &Value,
    database: &Database,
    observer: &PgPool,
    source: &mut Source,
    gate: &mut Option<gate::Gate>,
) -> FixtureResult<Value> {
    match command["command"].as_str() {
        Some("status") => source.facts(observer).await,
        Some("hold_audit" | "hold_subject") => {
            if gate.is_some() {
                return Err("one owned gate at a time".into());
            }
            *gate = Some(gate::Gate::hold(database, observer, source, command).await?);
            Ok(json!({"result":"held"}))
        }
        Some("wait_gate") => {
            gate.as_ref()
                .ok_or("owned gate absent")?
                .observe(observer)
                .await
        }
        Some("release") => {
            gate.take().ok_or("owned gate absent")?.release().await?;
            Ok(json!({"result":"released"}))
        }
        _ => Err("unsupported owned observation".into()),
    }
}
