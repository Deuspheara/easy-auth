use super::{
    actor::{self, Source},
    routing::WebState,
    types::*,
};
use crate::error::ApiError;
use axum::{
    Json,
    extract::{
        Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
};

#[utoipa::path(post,path="/v1/account/providers/oidc/unlink",request_body=SocialUnlinkInput,
    responses((status=204,description="Owned identity removed using a fresh retained method; no remote grant revocation"),(status=400),(status=401),(status=403),(status=413),(status=415),(status=503),(status=504)))]
pub(super) async fn unlink(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    _source: Source,
    body: Result<Json<SocialUnlinkInput>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    confirm(&input.confirmation, "unlink this account")?;
    let (session, _) = actor::current(&state.base, &headers, Some(input.expected_owner)).await?;
    state
        .services
        .linking
        .unlink(state.base.auth.realm(), &session, input.identity)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
