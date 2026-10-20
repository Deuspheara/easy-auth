use super::super::cookies::{SIGN_IN_COOKIES as COOKIES, require_anonymous};
use super::{routing::WebState, types::*};
use crate::{
    error::ApiError,
    handlers::{sessions::session_response, source_key},
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

#[utoipa::path(post, path = "/v1/oidc/sign-in/start", request_body = OidcSignInStartInput, params(("Origin"=String,Header),("Cookie"=Option<String>,Header)),
    responses((status=200,body=OidcSignInStartResponse),(status=400,description="Closed input rejected"),(status=401,description="Existing session or pending proof"),(status=403,description="Origin rejected"),(status=413,description="Body too large"),(status=415,description="JSON required"),(status=429,description="Admission denied"),(status=503,description="Storage/provider unavailable"),(status=504,description="Boundary timeout")))]
pub(super) async fn start(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<OidcSignInStartInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(_) = body?;
    require_anonymous(&state.base.browser, &headers)?;
    COOKIES.require_absent(&headers)?;
    let browser = Secret::generate()?;
    let source = source_key(source);
    let intent = OAuthIntent {
        browser: &browser,
        source: &source,
        purpose: OAuthPurpose::SignIn,
    };
    let start = state.services.source.transactions.begin(&intent).await?;
    let url = match state
        .services
        .source
        .exchange
        .authorization_url(&start, state.services.source.sign_in_scopes())
        .await
    {
        Ok(url) => url,
        Err(error) => {
            let _ = state
                .services
                .source
                .transactions
                .cancel(&intent, &start.state, &start.proof)
                .await;
            return Err(error.into());
        }
    };
    let mut response = Json(OidcSignInStartResponse {
        authorization_url: url.expose().to_owned(),
    })
    .into_response();
    COOKIES.set(&mut response, &state.base.browser, &browser, &start);
    Ok(response)
}

#[utoipa::path(post, path = "/v1/oidc/sign-in/finish", request_body = OidcSignInFinishInput, params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Session committed; protected session cookie issued"),(status=400,description="Closed input rejected"),(status=401,description="Session present or proof rejected"),(status=403,description="Origin rejected"),(status=413,description="Body too large"),(status=415,description="JSON required"),(status=429,description="Admission denied"),(status=503,description="Storage/provider unavailable"),(status=504,description="Boundary timeout")))]
pub(super) async fn finish(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<OidcSignInFinishInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    let result = complete(&state, &headers, &source_key(source), input).await;
    let mut response = match result {
        Ok(session) => session_response(&state.base, &session),
        Err(error) => ApiError::from(error).into_response(),
    };
    COOKIES.clear(&mut response, &state.base.browser);
    Ok(response)
}

async fn complete(
    state: &WebState,
    headers: &HeaderMap,
    source: &str,
    input: OidcSignInFinishInput,
) -> auth_core::Result<Secret> {
    require_anonymous(&state.base.browser, headers)?;
    let transaction = COOKIES.read(headers)?;
    let returned = Secret::parse(input.state)?;
    if returned.verifier() != transaction.state.verifier() {
        return Err(Error::Unauthorized);
    }
    let code = OidcAuthorizationCode::parse(input.code)?;
    let intent = OAuthIntent {
        browser: &transaction.browser,
        source,
        purpose: OAuthPurpose::SignIn,
    };
    let callback = OAuthCallback {
        redirect: state.services.source.policy.configuration().redirect(),
        issuer: input.issuer.as_deref(),
    };
    let context = state
        .services
        .source
        .transactions
        .consume(&intent, &transaction.state, transaction.proof, callback)
        .await?;
    let verified = state
        .services
        .source
        .exchange
        .exchange(context, code)
        .await?;
    let (_, session) = state
        .services
        .sign_in
        .finish(state.services.source.policy.map(verified)?)
        .await?;
    Ok(session)
}

#[utoipa::path(post, path = "/v1/oidc/sign-in/cancel", request_body = OidcSignInCancelInput, params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Pending sign-in cancelled; no current session revoked"),(status=400,description="Closed input rejected"),(status=401,description="Expired/invalid proof; local cookies cleared"),(status=403,description="Origin rejected"),(status=413,description="Body too large"),(status=415,description="JSON required"),(status=429,description="Admission denied"),(status=503,description="Storage unavailable; local cookies cleared"),(status=504,description="Boundary timeout")))]
pub(super) async fn cancel(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<OidcSignInCancelInput>, JsonRejection>,
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
    state: &WebState,
    headers: &HeaderMap,
    source: &str,
) -> auth_core::Result<()> {
    let transaction = COOKIES.read(headers)?;
    let intent = OAuthIntent {
        browser: &transaction.browser,
        source,
        purpose: OAuthPurpose::SignIn,
    };
    state
        .services
        .source
        .transactions
        .cancel(&intent, &transaction.state, &transaction.proof)
        .await
}
