use super::{cookies, routing::WebState, types::NoQuery};
use crate::error::ApiError;
use auth_core::{Error, Secret};
use axum::{
    Json,
    extract::{
        Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SamlOperationInput {
    #[serde(rename = "RelayState")]
    #[schema(min_length = 43, max_length = 43)]
    relay: String,
}
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum SamlOperationKind {
    SignIn,
    DeleteAccount,
}
#[derive(Serialize, ToSchema)]
pub(super) struct SamlOperationResponse {
    operation: SamlOperationKind,
}

/// Cookie-only same-origin selection. No storage, consumption, verification,
/// ownership or grant occurs; the selected finish must still enforce all checks.
#[utoipa::path(post,path="/v1/saml/operation",operation_id="selectSamlOperation",request_body=SamlOperationInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=SamlOperationResponse),(status=400),(status=401),(status=403),(status=413),(status=415)))]
pub(super) async fn select(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    body: Result<Json<SamlOperationInput>, JsonRejection>,
) -> Result<Json<SamlOperationResponse>, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    let returned = Secret::parse(input.relay)?;
    let matches = |cookies: &cookies::ProofCookies| {
        cookies
            .read(&headers)
            .is_ok_and(|tx| tx.relay.verifier() == returned.verifier())
    };
    let operation = match (
        matches(&cookies::SIGN_IN),
        matches(&cookies::ACCOUNT_DELETION),
    ) {
        (true, false) => SamlOperationKind::SignIn,
        (false, true) if state.services.deletion.is_some() => SamlOperationKind::DeleteAccount,
        _ => return Err(Error::Unauthorized.into()),
    };
    Ok(Json(SamlOperationResponse { operation }))
}
