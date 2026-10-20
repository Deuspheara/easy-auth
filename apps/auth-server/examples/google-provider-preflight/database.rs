//! Disposable local database ownership, never an application database migration.
use super::ProbeResult;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::net::IpAddr;
use url::Url;
use uuid::Uuid;

pub(super) struct Database {
    pub pool: PgPool,
    admin: PgPool,
    name: String,
}

impl Database {
    pub async fn create() -> ProbeResult<Self> {
        let mut url = Url::parse(&std::env::var("DATABASE_URL").map_err(|_| "database_setting")?)
            .map_err(|_| "database_setting")?;
        let host = url.host_str().ok_or("database_setting")?;
        let ip: IpAddr = host
            .trim_matches(['[', ']'])
            .parse()
            .map_err(|_| "local_database_required")?;
        if !ip.is_loopback()
            || !matches!(url.scheme(), "postgres" | "postgresql")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("local_database_required");
        }
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(url.as_str())
            .await
            .map_err(|_| "database_connection")?;
        // Generated identifier only. Never accept a caller-selected database to drop.
        let name = format!("easy_auth_google_probe_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&admin)
            .await
            .map_err(|_| "database_creation")?;
        url.set_path(&name);
        match PgPoolOptions::new()
            .max_connections(2)
            .connect(url.as_str())
            .await
        {
            Ok(pool) => Ok(Self { pool, admin, name }),
            Err(_) => {
                remove(&admin, &name).await?;
                admin.close().await;
                Err("owned_database_connection")
            }
        }
    }

    pub async fn close(self) -> ProbeResult<()> {
        self.pool.close().await;
        remove(&self.admin, &self.name).await?;
        self.admin.close().await;
        Ok(())
    }
}

async fn remove(admin: &PgPool, name: &str) -> ProbeResult<()> {
    sqlx::query(&format!("DROP DATABASE \"{name}\" WITH (FORCE)"))
        .execute(admin)
        .await
        .map_err(|_| "owned_database_cleanup")?;
    Ok(())
}
