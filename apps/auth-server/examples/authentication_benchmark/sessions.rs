//! Genuine repository transactions with synthetic proof enrollment in an owned DB.
use super::load::{Failure, Report, measure};
use auth_core::{Error, Repository, Secret};
use auth_postgres::Postgres;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

#[path = "sessions/fixture.rs"]
mod fixture;
use fixture::Fixture;

const OWNERS: usize = 8;
const POOL_CONNECTIONS: u32 = 8;

pub(super) async fn run() -> Report {
    let address = owned_database_url()?;
    let pool = PgPoolOptions::new()
        .max_connections(POOL_CONNECTIONS)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&address)
        .await?;
    let repository = Arc::new(Postgres::new(pool.clone()));
    let result = qualify_and_measure(repository).await;
    pool.close().await;
    result
}

fn owned_database_url() -> Result<String, Failure> {
    let address = std::env::var("DATABASE_URL")?;
    let parsed = url::Url::parse(&address)?;
    let name = parsed.path().strip_prefix('/').ok_or("missing database")?;
    let suffix = name
        .strip_prefix("auth50_")
        .ok_or("unowned database name")?;
    if parsed.scheme() != "postgresql"
        || parsed.host_str() != Some("127.0.0.1")
        || parsed.port().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || suffix.len() != 32
        || !suffix.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("owned loopback fixture required".into());
    }
    Ok(address)
}

async fn qualify_and_measure(repository: Arc<Postgres>) -> Report {
    repository.migrate().await?;
    let fixture = Arc::new(Fixture::create(repository).await?);
    // Establish real pool connections before timed workloads. This is not a
    // steady-state or open-loop capacity claim.
    let warm = fixture.clone();
    measure("warmup", OWNERS, 1, move |worker| {
        let warm = warm.clone();
        async move { warm.authenticate("independent_owners", worker).await }
    })
    .await?;
    let mut reports = Vec::new();
    for concurrency in [1, 2, 8] {
        for name in [
            "shared_session",
            "independent_owners",
            "unknown_session",
            "foreign_realm",
        ] {
            let fixture = fixture.clone();
            reports.push(
                measure(name, concurrency, 32, move |worker| {
                    let fixture = fixture.clone();
                    async move { fixture.authenticate(name, worker).await }
                })
                .await?,
            );
        }
    }
    fixture.check_revocation().await?;
    Ok(
        json!({"profile": "sessions", "pool_connections": POOL_CONNECTIONS,
        "fixture_owners": OWNERS, "warmup_operations": OWNERS, "foreign_realm_rejected": true,
        "revocation_rejected": true, "independent_owner_retained": true, "reports": reports}),
    )
}
