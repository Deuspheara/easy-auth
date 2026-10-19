//! Measurement-only support. Never linked into the authentication product.
use async_trait::async_trait;
use serde_json::json;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Barrier;

pub type Failure = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Failure>;
pub const SESSIONS: usize = 8;
pub const PASSWORD: &str = "comparison fixture password only";

#[async_trait]
pub trait Probe: Send + Sync {
    async fn validate(&self, session: usize) -> Result<bool>;
    async fn revoke(&self, session: usize) -> Result<()>;
}

pub async fn pool() -> Result<PgPool> {
    let options: PgConnectOptions = std::env::var("DATABASE_URL")?.parse()?;
    if !matches!(options.get_host(), "127.0.0.1" | "localhost")
        || !options
            .get_database()
            .unwrap_or_default()
            .starts_with("easy_auth_compare_")
    {
        return Err("probe requires a disposable easy_auth_compare_* database on loopback".into());
    }
    Ok(PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?)
}

async fn trial(
    probe: Arc<dyn Probe>,
    workers: usize,
    per_worker: usize,
) -> Result<serde_json::Value> {
    let barrier = Arc::new(Barrier::new(workers + 1));
    let mut tasks = Vec::new();
    for worker in 0..workers {
        let probe = probe.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(per_worker);
            barrier.wait().await;
            for _ in 0..per_worker {
                let start = Instant::now();
                if !probe.validate(worker).await? {
                    return Err::<Vec<f64>, Failure>("active session rejected".into());
                }
                latencies.push(start.elapsed().as_secs_f64() * 1_000.0);
            }
            Ok(latencies)
        }));
    }
    let start = Instant::now();
    barrier.wait().await;
    let mut latencies = Vec::new();
    for task in tasks {
        latencies.extend(task.await??);
    }
    let elapsed = start.elapsed().as_secs_f64();
    latencies.sort_by(f64::total_cmp);
    Ok(
        json!({"workers": workers, "requests": latencies.len(), "seconds": elapsed,
        "requests_per_second": latencies.len() as f64 / elapsed,
        "p50_ms": latencies[latencies.len()/2], "p95_ms": latencies[latencies.len()*95/100]}),
    )
}

pub async fn measure(name: &str, probe: Arc<dyn Probe>) -> Result<()> {
    // Let the external runner sample post-provisioning resident memory separately from hashing.
    println!("{}", json!({"phase": "ready", "project": name}));
    tokio::time::sleep(Duration::from_millis(500)).await;
    for session in 0..SESSIONS {
        for _ in 0..16 {
            if !probe.validate(session).await? {
                return Err("warmup rejected".into());
            }
        }
    }
    let mut trials = Vec::new();
    for workers in [1, 8] {
        for _ in 0..3 {
            trials.push(trial(probe.clone(), workers, 512 / workers).await?);
        }
    }
    let start = Instant::now();
    probe.revoke(0).await?;
    let revoke_ms = start.elapsed().as_secs_f64() * 1_000.0;
    for _ in 0..64 {
        if probe.validate(0).await? {
            return Err("revoked session accepted after revoke returned".into());
        }
    }
    if !probe.validate(1).await? {
        return Err("revocation affected a different user".into());
    }
    println!(
        "{}",
        json!({"phase": "result", "project": name, "pool_max": 10,
        "session_count": SESSIONS, "trials": trials, "revoke_ms": revoke_ms,
        "post_revoke_rejections": 64, "other_user_still_valid": true})
    );
    Ok(())
}
