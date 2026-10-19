//! Awaited revocation with sustained load from the other seven users.
use crate::{Probe, Result, SESSIONS};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use tokio::sync::Barrier;

pub(crate) const POST_REVOKE_CHECKS: usize = 64;
const MAX_BACKGROUND_REQUESTS: usize = 4096;

pub(crate) struct Observation {
    pub(crate) revoke_ms: f64,
    pub(crate) background_validations: usize,
}

async fn keep_validating(
    probe: Arc<dyn Probe>,
    session: usize,
    ready: Arc<Barrier>,
    stop: Arc<AtomicBool>,
) -> Result<usize> {
    // Every worker reaches the barrier even if its first call failed, so errors
    // propagate through the joined task instead of stranding the coordinator.
    let first = probe.validate(session).await;
    ready.wait().await;
    if !first? {
        return Err("background user's active session was rejected".into());
    }
    let mut completed = 0;
    while !stop.load(Ordering::Acquire) && completed < MAX_BACKGROUND_REQUESTS {
        if !probe.validate(session).await? {
            return Err("revocation affected another user's loaded session".into());
        }
        completed += 1;
    }
    if !stop.load(Ordering::Acquire) {
        return Err("bounded background load exhausted before revocation checks finished".into());
    }
    Ok(completed)
}

pub(crate) async fn under_load(probe: Arc<dyn Probe>) -> Result<Observation> {
    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(Barrier::new(SESSIONS));
    let mut workers = Vec::new();
    for session in 1..SESSIONS {
        workers.push(tokio::spawn(keep_validating(
            probe.clone(),
            session,
            ready.clone(),
            stop.clone(),
        )));
    }
    ready.wait().await;
    let started = Instant::now();
    probe.revoke(0).await?;
    let revoke_ms = started.elapsed().as_secs_f64() * 1_000.0;
    // These calls start after revoke returned. An earlier in-flight validation
    // is outside this guarantee; no timestamp heuristic labels it a failure.
    for _ in 0..POST_REVOKE_CHECKS {
        if probe.validate(0).await? {
            stop.store(true, Ordering::Release);
            return Err("revoked session accepted after revoke returned under load".into());
        }
    }
    let load_sustained = workers.iter().all(|worker| !worker.is_finished());
    stop.store(true, Ordering::Release);
    let mut background_validations = 0;
    for worker in workers {
        let completed = worker.await??;
        if completed == 0 {
            return Err("background worker performed no validations during revocation".into());
        }
        background_validations += completed;
    }
    if !load_sustained || !probe.validate(1).await? {
        return Err("background load ended early or another user lost its session".into());
    }
    Ok(Observation {
        revoke_ms,
        background_validations,
    })
}
