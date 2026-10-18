use crate::browser::read_cookie;
use crate::error::{ApiError, ErrorResponse};
use crate::router::AppState;
use auth_core::{Error, SessionInfo, SessionPage};
use axum::{
    Json,
    extract::{Query, State, rejection::QueryRejection},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub(crate) struct SessionQuery {
    /// Continue after the previous page's public UUID cursor.
    after: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct SessionResponse {
    id: Uuid,
    current: bool,
    created_at_ms: i64,
    last_seen_at_ms: i64,
    expires_at_ms: i64,
    idle_expires_at_ms: i64,
    /// Null for legacy sessions without trustworthy authentication-time provenance.
    authenticated_at_ms: Option<i64>,
}
impl From<SessionInfo> for SessionResponse {
    fn from(session: SessionInfo) -> Self {
        let SessionInfo {
            id,
            current,
            created_at_ms,
            last_seen_at_ms,
            expires_at_ms,
            idle_expires_at_ms,
            authenticated_at_ms,
        } = session;
        Self {
            id,
            current,
            created_at_ms,
            last_seen_at_ms,
            expires_at_ms,
            idle_expires_at_ms,
            authenticated_at_ms,
        }
    }
}
#[derive(Serialize, ToSchema)]
pub(crate) struct SessionListResponse {
    #[schema(max_items = 50)]
    sessions: Vec<SessionResponse>,
    next: Option<Uuid>,
}
impl From<SessionPage> for SessionListResponse {
    fn from(page: SessionPage) -> Self {
        Self {
            sessions: page
                .sessions
                .into_iter()
                .map(SessionResponse::from)
                .collect(),
            next: page.next,
        }
    }
}

#[utoipa::path(get, path="/v1/sessions", params(SessionQuery, ("Cookie"=String,Header)),
    responses((status=200,body=SessionListResponse,description="At most 50 owned active sessions; public metadata only; next is a UUID cursor"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(crate) async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<SessionQuery>, QueryRejection>,
) -> Result<Json<SessionListResponse>, ApiError> {
    let Query(query) = query.map_err(|_| Error::InvalidInput)?;
    let current = read_cookie(&headers, state.browser.session_name())?;
    let page = state.auth.list_sessions(&current, query.after).await?;
    Ok(Json(page.into()))
}
