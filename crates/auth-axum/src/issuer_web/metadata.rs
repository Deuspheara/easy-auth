use super::{
    routing::WebState,
    types::{DiscoverySchema, JwksSchema, NoQuery},
};
use crate::error::ApiError;
use axum::{
    Json,
    extract::{Query, State, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[utoipa::path(get,path="/.well-known/openid-configuration",responses((status=200,body=super::types::DiscoverySchema),(status=400),(status=503),(status=504)))]
pub(super) async fn discovery(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    Ok(Json(DiscoverySchema::from(
        state.services.metadata.discovery().await?,
    ))
    .into_response())
}
#[utoipa::path(get,path="/oidc/jwks",responses((status=200,body=super::types::JwksSchema),(status=400),(status=503),(status=504)))]
pub(super) async fn jwks(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    Ok(Json(JwksSchema::try_from(state.services.metadata.jwks().await?)?).into_response())
}
