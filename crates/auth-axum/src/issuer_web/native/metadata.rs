use super::super::types::{DiscoverySchema, NoQuery};
use super::services::IssuerNativeWebServices;
use crate::error::ApiError;
use axum::{
    Json,
    extract::{Query, State, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
#[utoipa::path(get,path="/.well-known/openid-configuration",operation_id="nativeIssuerDiscovery",responses((status=200,body=DiscoverySchema),(status=400),(status=503),(status=504)))]
pub(super) async fn discovery(
    State(services): State<IssuerNativeWebServices>,
    query: Result<Query<NoQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let mut document = DiscoverySchema::from(services.base.metadata.discovery().await?);
    document.grant_types_supported.push("refresh_token".into());
    document.scopes_supported.push("offline_access".into());
    Ok(Json(document).into_response())
}
