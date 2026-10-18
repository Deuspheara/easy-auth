use crate::error::{ApiError, ErrorResponse};
use crate::router::AppState;
use axum::{extract::State, http::StatusCode};

#[utoipa::path(get, path = "/readyz", responses((status = 200), (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
pub(crate) async fn ready(State(state): State<AppState>) -> Result<StatusCode, ApiError> {
    state.auth.ready().await?;
    Ok(StatusCode::OK)
}
#[utoipa::path(get, path = "/healthz", responses((status = 200), (status = 504, body = ErrorResponse)))]
pub(crate) async fn health() -> StatusCode {
    StatusCode::OK
}
