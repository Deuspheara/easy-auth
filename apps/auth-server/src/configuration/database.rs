use super::required_setting;
use auth_postgres::Postgres;
use sqlx::postgres::PgPoolOptions;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub(super) async fn repository(realm: Uuid) -> Result<Arc<Postgres>, Box<dyn std::error::Error>> {
    let database_url = required_setting("DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .map_err(|_| "database connection failed")?;
    let repository = Postgres::new(pool);
    repository.migrate().await?;
    repository.ensure_realm(realm).await?;
    Ok(Arc::new(repository))
}
