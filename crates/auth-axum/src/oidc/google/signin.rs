use super::{
    binding::{self, Source},
    routing::WebState,
    types::*,
};
use crate::{
    error::ApiError,
    handlers::{sessions::session_response, source_key},
    oidc::cookies::{GOOGLE_SIGN_IN_COOKIES as COOKIES, Transaction, require_anonymous},
};
use auth_core::{GoogleAuthorizationResponse, OAuthIntent, OAuthPurpose, Secret};
use axum::{
    Json,
    extract::{
        Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

#[utoipa::path(post,path="/v1/google/sign-in/start",request_body=GoogleEmptyInput,
    params(("Origin"=String,Header),("Cookie"=Option<String>,Header)),
    responses((status=200,body=GoogleStartResponse),(status=400,description="Closed input rejected"),(status=401,description="Existing session or pending proof"),(status=403,description="Origin rejected"),(status=413,description="Body too large"),(status=415,description="JSON required"),(status=429,description="Admission denied"),(status=503,description="Provider/storage unavailable"),(status=504,description="Boundary timeout")))]
pub(super) async fn start(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<GoogleEmptyInput>, JsonRejection>,
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
    let mut response = Json(GoogleStartResponse {
        authorization_url: start.authorization_url.expose().to_owned(),
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

#[utoipa::path(post,path="/v1/google/sign-in/finish",request_body=GoogleCallbackInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Local session committed; protected cookie issued"),(status=400,description="Closed input rejected"),(status=401,description="Binding/claim rejection or bound provider denial"),(status=403,description="Origin rejected"),(status=413,description="Body too large"),(status=415,description="JSON required"),(status=429,description="Admission denied"),(status=503,description="Provider/profile/storage unavailable"),(status=504,description="Boundary timeout")))]
pub(super) async fn finish(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<GoogleCallbackInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    require_anonymous(&state.base.browser, &headers)?;
    let (transaction, returned) = binding::callback(&input.query, &COOKIES, &headers)?;
    let result = complete(&state, &source_key(source), transaction, returned).await;
    let mut response = match result {
        Ok(session) => session_response(&state.base, &session),
        Err(error) => ApiError::from(error).into_response(),
    };
    COOKIES.clear(&mut response, &state.base.browser);
    Ok(response)
}
async fn complete(
    state: &WebState,
    source: &str,
    transaction: Transaction,
    returned: GoogleAuthorizationResponse,
) -> auth_core::Result<Secret> {
    let intent = OAuthIntent {
        browser: &transaction.browser,
        source,
        purpose: OAuthPurpose::SignIn,
    };
    let completion = state
        .services
        .authorization
        .finish(
            &intent,
            &transaction.state,
            transaction.proof,
            state.services.policy.configuration().redirect(),
            returned,
        )
        .await?;
    let identity = state.services.policy.map(binding::verified(completion)?)?;
    let (_, session) = state.services.sign_in.finish(identity).await?;
    Ok(session)
}

#[utoipa::path(post,path="/v1/google/sign-in/cancel",request_body=GoogleEmptyInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Bound pending sign-in cancelled; ambient session retained"),(status=400,description="Closed input rejected"),(status=401,description="Binding rejected; own proof cookies cleared"),(status=403,description="Origin rejected"),(status=413,description="Body too large"),(status=415,description="JSON required"),(status=429,description="Admission denied"),(status=503,description="Storage unavailable; own proof cookies cleared"),(status=504,description="Boundary timeout")))]
pub(super) async fn cancel(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<GoogleEmptyInput>, JsonRejection>,
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
    state
        .services
        .authorization
        .cancel(
            &OAuthIntent {
                browser: &transaction.browser,
                source,
                purpose: OAuthPurpose::SignIn,
            },
            &transaction.state,
            &transaction.proof,
        )
        .await
}
