use super::*;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::atomic::Ordering;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    failure: bool,
}

// Only the dedicated never-deploy owned fixture selects these loopback routes.
// They observe finite counts/run a preconfigured worker; they cannot upload a
// token, choose a source/key/endpoint or mint a local authentication proof.
pub(in super::super) fn routes(fixture: Arc<Fixture>) -> Router {
    Router::new()
        .route("/fixture/grants", get(snapshot))
        .route("/fixture/grants/run", post(run))
        .layer(DefaultBodyLimit::max(128))
        .with_state(fixture)
}
async fn snapshot(
    State(fixture): State<Arc<Fixture>>,
) -> std::result::Result<Json<observations::Snapshot>, StatusCode> {
    fixture
        .snapshot()
        .await
        .map(Json)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
async fn run(
    State(fixture): State<Arc<Fixture>>,
    Json(attempt): Json<Attempt>,
) -> std::result::Result<Json<serde_json::Value>, StatusCode> {
    fixture
        .http
        .failure
        .store(attempt.failure, Ordering::SeqCst);
    let outcome = fixture
        .worker
        .run_once()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let outcome = match outcome {
        AppleRevocationOutcome::Idle => "idle",
        AppleRevocationOutcome::Confirmed => "confirmed",
        AppleRevocationOutcome::Deferred(AppleRevocationFailure::Configuration) => {
            "deferred_configuration"
        }
        AppleRevocationOutcome::Deferred(_) => "deferred_other",
        AppleRevocationOutcome::Stale => "stale",
    };
    Ok(Json(serde_json::json!({"outcome":outcome})))
}
