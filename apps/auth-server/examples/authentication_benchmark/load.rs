//! Closed-loop, bounded workers. Record every completion, including refusals.
use auth_core::Error;
use serde_json::{Value, json};
use std::{future::Future, sync::Arc, time::Instant};
use tokio::{sync::Barrier, task::JoinSet};

pub(super) type Failure = Box<dyn std::error::Error + Send + Sync>;
pub(super) type Report = Result<Value, Failure>;

pub(super) async fn measure<F, Fut>(
    name: &str,
    concurrency: usize,
    per_worker: usize,
    operation: F,
) -> Report
where
    F: Fn(usize) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = auth_core::Result<()>> + Send,
{
    let operation = Arc::new(operation);
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let mut workers = JoinSet::new();
    for worker in 0..concurrency {
        let operation = operation.clone();
        let barrier = barrier.clone();
        workers.spawn(async move {
            let mut samples = Vec::with_capacity(per_worker);
            barrier.wait().await;
            for _ in 0..per_worker {
                let start = Instant::now();
                let outcome = match operation(worker).await {
                    Ok(()) => "success",
                    Err(Error::Unauthorized) => "unauthorized",
                    Err(Error::RateLimited) => "rate_limited",
                    Err(_) => return Err("unexpected operation failure"),
                };
                samples.push((start.elapsed().as_secs_f64() * 1000.0, outcome));
            }
            Ok(samples)
        });
    }
    let start = Instant::now();
    barrier.wait().await;
    let mut samples = Vec::with_capacity(concurrency * per_worker);
    while let Some(worker) = workers.join_next().await {
        samples.extend(worker??);
    }
    summarize(
        name,
        concurrency,
        per_worker,
        start.elapsed().as_secs_f64(),
        samples,
    )
}

fn summarize(
    name: &str,
    concurrency: usize,
    per_worker: usize,
    wall_seconds: f64,
    samples: Vec<(f64, &str)>,
) -> Report {
    if samples.len() != concurrency * per_worker || wall_seconds <= 0.0 {
        return Err("incomplete benchmark samples".into());
    }
    let mut outcomes = serde_json::Map::new();
    for outcome in ["success", "unauthorized", "rate_limited"] {
        let mut values: Vec<f64> = samples
            .iter()
            .filter(|s| s.1 == outcome)
            .map(|s| s.0)
            .collect();
        values.sort_by(f64::total_cmp);
        let latency = if values.is_empty() {
            Value::Null
        } else {
            let percentile = |rank: usize| values[(values.len() * rank).div_ceil(100) - 1];
            json!({"p50": percentile(50), "p95": percentile(95), "p99": percentile(99),
                "max": values.last(), "samples": values})
        };
        outcomes.insert(
            outcome.into(),
            json!({"count": values.len(),
            "per_second": values.len() as f64 / wall_seconds, "latency_ms": latency}),
        );
    }
    Ok(
        json!({"name": name, "concurrency": concurrency, "per_worker": per_worker,
        "attempts": samples.len(), "wall_seconds": wall_seconds,
        "attempts_per_second": samples.len() as f64 / wall_seconds, "outcomes": outcomes}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_work_is_not_counted_as_successful_capacity() {
        let report = summarize(
            "control",
            2,
            2,
            2.0,
            vec![
                (4.0, "success"),
                (2.0, "success"),
                (0.1, "rate_limited"),
                (1.0, "unauthorized"),
            ],
        )
        .unwrap();
        assert_eq!(report["outcomes"]["success"]["per_second"], 1.0);
        assert_eq!(report["outcomes"]["success"]["latency_ms"]["p50"], 2.0);
        assert_eq!(report["outcomes"]["success"]["latency_ms"]["p99"], 4.0);
        assert_eq!(report["outcomes"]["rate_limited"]["count"], 1);
        assert!(summarize("incomplete", 2, 2, 1.0, vec![(1.0, "success")]).is_err());
    }
}
