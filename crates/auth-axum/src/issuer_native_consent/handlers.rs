use super::{routing::WebState, types::*};
use crate::issuer_consent::cookies;
use crate::{browser::read_cookie, error::ApiError};
use auth_core::{Error, Secret};
use axum::{
    Json,
    extract::{
        Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

type ClosedQuery = Result<Query<NoQuery>, QueryRejection>;

#[utoipa::path(post,path="/v1/oidc/native/consent/prepare",operation_id="nativeConsentPrepare",request_body=NativeConsentInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=NativeConsentPreview),(status=400),(status=401),(status=403),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn prepare(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<NativeConsentInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    let current = read_cookie(&headers, state.base.browser.session_name())?;
    cookies::require_absent(&headers)?;
    let browser = Secret::generate()?;
    let pending = state
        .authorization
        .prepare(&current, &browser, &input.input())
        .await?;
    let mut response = Json(NativeConsentPreview::from(&pending)).into_response();
    cookies::set(
        &mut response,
        &state.base.browser,
        &browser,
        pending.authorization(),
        pending.handle(),
    );
    Ok(response)
}

#[utoipa::path(post,path="/v1/oidc/native/consent/approve",operation_id="nativeConsentApprove",request_body=NativeConsentDecision,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=NativeConsentReturn),(status=400),(status=401),(status=403),(status=413),(status=415),(status=503),(status=504)))]
pub(super) async fn approve(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<NativeConsentDecision>, JsonRejection>,
) -> Result<Response, ApiError> {
    decide(state, query, headers, body, true).await
}
#[utoipa::path(post,path="/v1/oidc/native/consent/cancel",operation_id="nativeConsentCancel",request_body=NativeConsentDecision,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=NativeConsentReturn),(status=400),(status=401),(status=403),(status=413),(status=415),(status=503),(status=504)))]
pub(super) async fn cancel(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<NativeConsentDecision>, JsonRejection>,
) -> Result<Response, ApiError> {
    decide(state, query, headers, body, false).await
}
async fn decide(
    state: WebState,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<NativeConsentDecision>, JsonRejection>,
    approve: bool,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    let current = read_cookie(&headers, state.base.browser.session_name())?;
    let (browser, handle) = cookies::read(&headers)?;
    if cookies::operation(&headers)? != input.authorization {
        return Err(Error::Unauthorized.into());
    }
    let returned = if approve {
        state
            .authorization
            .approve(&current, &browser, &handle, input.authorization)
            .await?
    } else {
        state
            .authorization
            .cancel(&current, &browser, &handle, input.authorization)
            .await?
    };
    // Errors never clear/replace a newer tab's proofs; successful decisions alone
    // clear these cookies. Original state/caps still gate every database operation.
    let mut response = Json(NativeConsentReturn {
        redirect_uri: returned.url().to_owned(),
    })
    .into_response();
    cookies::clear(&mut response, &state.base.browser);
    Ok(response)
}

#[utoipa::path(post,path="/v1/oidc/native/consent/resume",operation_id="nativeConsentResume",request_body=NativeConsentResume,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=NativeConsentPreview),(status=400),(status=401),(status=403),(status=413),(status=415),(status=503),(status=504)))]
pub(super) async fn resume(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<NativeConsentResume>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(_) = body?;
    let current = read_cookie(&headers, state.base.browser.session_name())?;
    let (browser, handle) = cookies::read(&headers)?;
    let operation = cookies::operation(&headers)?;
    match state
        .authorization
        .preview(&current, &browser, &handle, operation)
        .await
    {
        Ok(preview) => Ok(Json(NativeConsentPreview::from(preview)).into_response()),
        Err(Error::Unauthorized) => {
            // Expired/revoked/stale context cannot authorize a decision. Clearing
            // only this selected transport allows a new request; no grant occurs.
            let mut response = ApiError::from(Error::Unauthorized).into_response();
            cookies::clear(&mut response, &state.base.browser);
            Ok(response)
        }
        Err(error) => Err(error.into()),
    }
}
