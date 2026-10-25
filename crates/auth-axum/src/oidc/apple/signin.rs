use super::{routing::WebState, types::*};
use crate::{
    browser::require_anonymous,
    error::ApiError,
    handlers::{sessions::session_response, source_key},
    oidc::cookies::APPLE_SIGN_IN_COOKIES as COOKIES,
};
use auth_core::{AppleAuthorizationResponse, Error, OAuthIntent, OAuthPurpose, Secret};
use axum::{
    Extension, Json,
    extract::{
        ConnectInfo, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
type Source = Option<Extension<ConnectInfo<SocketAddr>>>;

#[utoipa::path(post,path="/v1/apple/sign-in/start",request_body=AppleEmptyInput,
    responses((status=200,body=AppleStartResponse),(status=400),(status=401),(status=403),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn start(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<AppleEmptyInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(_) = body?;
    require_anonymous(&state.base.browser, &headers)?;
    COOKIES.require_absent(&headers)?;
    let browser = Secret::generate()?;
    let source = source_key(source);
    let start = state
        .services
        .authorization
        .begin(&OAuthIntent {
            browser: &browser,
            source: &source,
            purpose: OAuthPurpose::SignIn,
        })
        .await?;
    let url = start.request.web_url().ok_or(Error::Unavailable)?;
    let mut response = Json(AppleStartResponse {
        authorization_url: url.to_owned(),
    })
    .into_response();
    COOKIES.set(
        &mut response,
        &state.base.browser,
        &browser,
        &start.transaction,
    );
    Ok(response)
}

#[utoipa::path(post,path="/v1/apple/sign-in/finish",request_body=AppleCallbackInput,
    responses((status=204,description="Session cookie only after verified local commit"),(status=400),(status=401),(status=403),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn finish(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<AppleCallbackInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    require_anonymous(&state.base.browser, &headers)?;
    let transaction = COOKIES.read(&headers)?;
    let returned = AppleAuthorizationResponse::parse(&input.response)?;
    // Stale/malformed returns must not clear a newer pending operation.
    if returned.state().verifier() != transaction.state.verifier() {
        return Err(Error::Unauthorized.into());
    }
    let result = state
        .services
        .complete_sign_in(&source_key(source), transaction, returned)
        .await;
    let mut response = match result {
        Ok(session) => session_response(&state.base, &session),
        Err(error) => ApiError::from(error).into_response(),
    };
    COOKIES.clear(&mut response, &state.base.browser);
    Ok(response)
}
#[utoipa::path(post,path="/v1/apple/sign-in/cancel",request_body=AppleCancelInput,
    responses((status=204,description="Owned pending operation cancelled; session retained"),(status=400),(status=401),(status=403),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn cancel(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<AppleCancelInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    let transaction = COOKIES.read(&headers)?;
    if let Some(state_hint) = input.state
        && Secret::parse(state_hint)?.verifier() != transaction.state.verifier()
    {
        return Err(Error::Unauthorized.into());
    }
    let source = source_key(source);
    let result = state
        .services
        .authorization
        .cancel(
            &OAuthIntent {
                browser: &transaction.browser,
                source: &source,
                purpose: OAuthPurpose::SignIn,
            },
            &transaction.state,
            &transaction.proof,
        )
        .await;
    let mut response = match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => ApiError::from(error).into_response(),
    };
    COOKIES.clear(&mut response, &state.base.browser);
    Ok(response)
}
