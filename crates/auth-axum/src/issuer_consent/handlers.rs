use super::{cookies, routing::WebState, types::*};
use crate::{browser::read_cookie, error::ApiError};
use auth_core::{Error, IssuerAuthorizationInput, Secret};
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

#[utoipa::path(post,path="/v1/oidc/consent/prepare",request_body=IssuerConsentInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=IssuerConsentPreview),(status=400),(status=401),(status=403),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn prepare(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<IssuerConsentInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    let current = read_cookie(&headers, state.base.browser.session_name())?;
    cookies::require_absent(&headers)?;
    let browser = Secret::generate()?;
    let pending = state
        .authorization
        .prepare(
            &current,
            &browser,
            &IssuerAuthorizationInput {
                client: input.client_id,
                response_type: &input.response_type,
                redirect_uri: &input.redirect_uri,
                scope: &input.scope,
                state: &input.state,
                nonce: &input.nonce,
                code_challenge: &input.code_challenge,
                code_challenge_method: &input.code_challenge_method,
            },
        )
        .await?;
    let mut response = Json(IssuerConsentPreview {
        authorization: pending.authorization(),
        client_id: pending.client(),
        redirect_uri: pending.redirect_uri().to_owned(),
        expires_at_us: pending.expires_at_us(),
    })
    .into_response();
    cookies::set(
        &mut response,
        &state.base.browser,
        &browser,
        pending.authorization(),
        pending.handle(),
    );
    Ok(response)
}

#[utoipa::path(post,path="/v1/oidc/consent/approve",request_body=IssuerConsentDecision,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=IssuerConsentReturn),(status=400),(status=401),(status=403),(status=413),(status=415),(status=503),(status=504)))]
pub(super) async fn approve(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<IssuerConsentDecision>, JsonRejection>,
) -> Result<Response, ApiError> {
    decide(state, query, headers, body, true).await
}
#[utoipa::path(post,path="/v1/oidc/consent/cancel",request_body=IssuerConsentDecision,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=IssuerConsentReturn),(status=400),(status=401),(status=403),(status=413),(status=415),(status=503),(status=504)))]
pub(super) async fn cancel(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<IssuerConsentDecision>, JsonRejection>,
) -> Result<Response, ApiError> {
    decide(state, query, headers, body, false).await
}
async fn decide(
    state: WebState,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<IssuerConsentDecision>, JsonRejection>,
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
    let mut response = Json(IssuerConsentReturn {
        redirect_uri: returned.url().to_owned(),
    })
    .into_response();
    cookies::clear(&mut response, &state.base.browser);
    Ok(response)
}

#[utoipa::path(post,path="/v1/oidc/consent/resume",request_body=IssuerConsentResume,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=IssuerConsentPreview),(status=400),(status=401),(status=403),(status=413),(status=415),(status=503),(status=504)))]
pub(super) async fn resume(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<IssuerConsentResume>, JsonRejection>,
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
        Ok(preview) => Ok(Json(IssuerConsentPreview {
            authorization: preview.authorization,
            client_id: preview.client,
            redirect_uri: preview.redirect_uri,
            expires_at_us: preview.expires_at_us,
        })
        .into_response()),
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
