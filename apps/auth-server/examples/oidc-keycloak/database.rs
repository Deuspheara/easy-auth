use super::FixtureResult;
use sqlx::{PgPool, postgres::PgPoolOptions};
use url::Url;

pub(super) struct Database {
    pub name: String,
    pub pool: PgPool,
    admin: PgPool,
}
async fn admin() -> FixtureResult<(PgPool, Url)> {
    let url = Url::parse(&std::env::var("DATABASE_URL")?)?;
    if !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")) {
        return Err("owned fixture requires loopback PostgreSQL".into());
    }
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(url.as_str())
        .await?;
    Ok((pool, url))
}
impl Database {
    pub async fn new(name: &str) -> FixtureResult<Self> {
        validate_name(name)?;
        let (admin, mut url) = admin().await?;
        let name = name.to_owned();
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&admin)
            .await?;
        url.set_path(&name);
        match PgPoolOptions::new()
            .max_connections(4)
            .connect(url.as_str())
            .await
        {
            Ok(pool) => Ok(Self { name, pool, admin }),
            Err(error) => {
                sqlx::query(&format!("DROP DATABASE \"{name}\""))
                    .execute(&admin)
                    .await?;
                Err(error.into())
            }
        }
    }
    pub async fn close(self) -> FixtureResult<()> {
        self.pool.close().await;
        sqlx::query(&format!("DROP DATABASE \"{}\" WITH (FORCE)", self.name))
            .execute(&self.admin)
            .await
            .inspect_err(|error| {
                let category = match error
                    .as_database_error()
                    .and_then(|value| value.code())
                    .as_deref()
                {
                    Some("55006") => "active_connections",
                    Some("3D000") => "missing_database",
                    _ => "storage_failure",
                };
                let _ = super::send(serde_json::json!({"cleanup_failure":category}));
            })?;
        self.admin.close().await;
        Ok(())
    }
}
/// Emergency cleanup accepts only the exact random name reported to its owner.
pub(super) async fn remove_owned(name: &str) -> FixtureResult<()> {
    validate_name(name)?;
    let (admin, _) = admin().await?;
    sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
        .execute(&admin)
        .await?;
    admin.close().await;
    Ok(())
}
fn validate_name(name: &str) -> FixtureResult<()> {
    let suffix = name
        .strip_prefix("easy_auth_oidc_")
        .ok_or("invalid owned name")?;
    if suffix.len() != 32 || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid owned name".into());
    }
    Ok(())
}
