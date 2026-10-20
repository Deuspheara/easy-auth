use super::super::cookies::ACCOUNT_DELETION_COOKIES as COOKIES;
use super::{routing::DeletionState, types::*};
use crate::{
    browser::{clear_auth_cookies, read_cookie},
    error::ApiError,
    handlers::source_key,
};
use auth_core::{Error, OAuthCallback, OAuthIntent, OAuthPurpose, OidcAuthorizationCode, Secret};
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

#[utoipa::path(post, path = "/v1/account/provider-delete/start", request_body = DeletionStartInput, params(("Origin" = String, Header), ("Cookie" = String, Header)),
    responses((status = 200, body = DeletionStartResponse), (status = 400, description = "Invalid confirmation/input"), (status = 401, description = "Current provider session required"), (status = 403, description = "Origin rejected"), (status = 429, description = "Admission denied"), (status = 503, description = "Storage or provider unavailable")))]
pub(super) async fn start(
    State(state): State<DeletionState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<DeletionStartInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    confirm(&input.confirmation)?;
    COOKIES.require_absent(&headers)?;
    let purpose = purpose(&state, &headers).await?;
    let browser = Secret::generate()?;
    let source = source_key(source);
    let intent = OAuthIntent {
        browser: &browser,
        source: &source,
        purpose,
    };
    let start = state.services.source.transactions.begin(&intent).await?;
    let url = match state
        .services
        .source
        .exchange
        .reauthentication_url(&start, &[])
        .await
    {
        Ok(url) => url,
        Err(error) => {
            // No cookies have been issued. Best-effort denial-only cleanup; an
            // unavailable repository may retain the bounded row until expiry.
            let _ = state
                .services
                .source
                .transactions
                .cancel(&intent, &start.state, &start.proof)
                .await;
            return Err(error.into());
        }
    };
    let mut response = Json(DeletionStartResponse {
        authorization_url: url.expose().to_owned(),
    })
    .into_response();
    COOKIES.set(&mut response, &state.base.browser, &browser, &start);
    Ok(response)
}

#[utoipa::path(post, path = "/v1/account/provider-delete/finish", request_body = DeletionFinishInput, params(("Origin" = String, Header), ("Cookie" = String, Header)),
    responses((status = 204, description = "Account deletion committed; cookies cleared; no session issued"), (status = 400, description = "Invalid confirmation/input"), (status = 401, description = "Proof or current authority rejected"), (status = 403, description = "Origin rejected"), (status = 429, description = "Admission denied"), (status = 503, description = "Storage or provider unavailable")))]
pub(super) async fn finish(
    State(state): State<DeletionState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<DeletionFinishInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    confirm(&input.confirmation)?;
    let result = complete(&state, &headers, &source_key(source), input).await;
    Ok(match result {
        Ok(()) => clear_auth_cookies(&state.base.browser),
        Err(error) => {
            let mut response = ApiError::from(error).into_response();
            COOKIES.clear(&mut response, &state.base.browser);
            response
        }
    })
}

async fn complete(
    state: &DeletionState,
    headers: &HeaderMap,
    source: &str,
    input: DeletionFinishInput,
) -> auth_core::Result<()> {
    let transaction = COOKIES.read(headers)?;
    let returned_state = Secret::parse(input.state)?;
    if returned_state.verifier() != transaction.state.verifier() {
        return Err(Error::Unauthorized);
    }
    let code = OidcAuthorizationCode::parse(input.code)?;
    let intent = OAuthIntent {
        browser: &transaction.browser,
        source,
        purpose: purpose(state, headers).await?,
    };
    let callback = OAuthCallback {
        redirect: state.services.source.policy.configuration().redirect(),
        issuer: input.issuer.as_deref(),
    };
    let exchange = state
        .services
        .source
        .transactions
        .consume(&intent, &transaction.state, transaction.proof, callback)
        .await?;
    let verified = state
        .services
        .source
        .exchange
        .exchange(exchange, code)
        .await?;
    state
        .services
        .deletion
        .finish(state.services.source.policy.map(verified)?)
        .await
}

#[utoipa::path(post, path = "/v1/account/provider-delete/cancel", request_body = DeletionCancelInput, params(("Origin" = String, Header), ("Cookie" = String, Header)),
    responses((status = 204, description = "Pending attempt cancelled; no provider exchange or session issued"), (status = 401, description = "Expired or invalid binding; local proof cookies cleared"), (status = 403, description = "Origin rejected"), (status = 429, description = "Admission denied"), (status = 503, description = "Storage unavailable; local proof cookies cleared")))]
pub(super) async fn cancel(
    State(state): State<DeletionState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<DeletionCancelInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(_) = body?;
    let result = cancel_pending(&state, &headers, &source_key(source)).await;
    let mut response = match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => ApiError::from(error).into_response(),
    };
    COOKIES.clear(&mut response, &state.base.browser);
    Ok(response)
}
async fn cancel_pending(
    state: &DeletionState,
    headers: &HeaderMap,
    source: &str,
) -> auth_core::Result<()> {
    let transaction = COOKIES.read(headers)?;
    let intent = OAuthIntent {
        browser: &transaction.browser,
        source,
        purpose: purpose(state, headers).await?,
    };
    state
        .services
        .source
        .transactions
        .cancel(&intent, &transaction.state, &transaction.proof)
        .await
}
async fn purpose(state: &DeletionState, headers: &HeaderMap) -> auth_core::Result<OAuthPurpose> {
    let session = read_cookie(headers, state.base.browser.session_name())?;
    let user = state.base.auth.authenticate(&session).await?;
    Ok(OAuthPurpose::DeleteProviderAccount {
        user: user.id,
        session: session.verifier(),
    })
}
