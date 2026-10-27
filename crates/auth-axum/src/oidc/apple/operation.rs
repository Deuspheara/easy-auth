use super::types::NoQuery;
use crate::{error::ApiError, oidc::cookies::APPLE_SIGN_IN_COOKIES};
use auth_core::{Error, Secret};
use axum::{
    Json,
    extract::{
        Query,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AppleReturnOperationInput {
    /// Public returned state only. No code, token, profile or private proof.
    #[schema(min_length = 43, max_length = 43)]
    state: String,
}
#[derive(Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum AppleReturnOperation {
    SignIn,
    LinkIdentity,
}

// Presentation hint only: no DB, consumption, cancellation, cookie or credential
// mutation. The cross-site delivery remains completely cookie/storage-free.
#[utoipa::path(post,path="/v1/apple/return-operation",request_body=AppleReturnOperationInput,
    responses((status=200,body=AppleReturnOperation,description="Non-authoritative fixed UI selection using unique matching private state cookie"),(status=400),(status=401),(status=403),(status=413),(status=415),(status=504)))]
pub(super) async fn operation(
    #[cfg(feature = "social-linking-web")] selected: Option<
        axum::Extension<crate::oidc::social::SocialLinkingSelected>,
    >,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    body: Result<Json<AppleReturnOperationInput>, JsonRejection>,
) -> Result<Json<AppleReturnOperation>, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    let returned = Secret::parse(input.state)?;
    let matches = |cookies: &crate::oidc::cookies::Cookies| -> auth_core::Result<bool> {
        Ok(cookies
            .state_hint(&headers)?
            .is_some_and(|s| s.verifier() == returned.verifier()))
    };
    let signin = matches(&APPLE_SIGN_IN_COOKIES)?;
    #[cfg(feature = "social-linking-web")]
    {
        let linking = selected.is_some() && matches(&crate::oidc::cookies::APPLE_LINK_COOKIES)?;
        match (signin, linking) {
            (true, false) => Ok(Json(AppleReturnOperation::SignIn)),
            (false, true) => Ok(Json(AppleReturnOperation::LinkIdentity)),
            _ => Err(Error::Unauthorized.into()),
        }
    }
    #[cfg(not(feature = "social-linking-web"))]
    if signin {
        Ok(Json(AppleReturnOperation::SignIn))
    } else {
        Err(Error::Unauthorized.into())
    }
}
