use super::{StartupResult, required_setting, setting};
use auth_postgres::Postgres;
use sqlx::postgres::PgPoolOptions;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

const RUNTIME_CONNECTIONS: u32 = 10;

pub(super) async fn repository(realm: Uuid) -> Result<Arc<Postgres>, Box<dyn std::error::Error>> {
    let action = schema_action()?;
    let repository = Postgres::new(pool(RUNTIME_CONNECTIONS).await?);
    match action {
        SchemaAction::Run => repository.migrate().await?,
        SchemaAction::Verify => repository.verify_schema().await?,
    }
    repository.ensure_realm(realm).await?;
    Ok(Arc::new(repository))
}

pub(crate) async fn pool(max_connections: u32) -> StartupResult<sqlx::PgPool> {
    let database_url = required_setting("DATABASE_URL")?;
    PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .map_err(|_| "database connection failed".into())
}

enum SchemaAction {
    Run,
    Verify,
}

fn schema_action() -> StartupResult<SchemaAction> {
    match setting("AUTH_DATABASE_MIGRATIONS", "run")?.as_str() {
        "run" => Ok(SchemaAction::Run),
        "verify" => Ok(SchemaAction::Verify),
        _ => Err("AUTH_DATABASE_MIGRATIONS must be run or verify".into()),
    }
}
