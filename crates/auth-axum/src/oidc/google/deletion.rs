use super::{
    binding::{self, Source},
    routing::WebState,
    types::*,
};
use crate::{
    browser::clear_auth_cookies,
    error::ApiError,
    handlers::source_key,
    oidc::cookies::{GOOGLE_DELETION_COOKIES as COOKIES, Transaction},
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

#[utoipa::path(post,path="/v1/account/google-delete/start",request_body=GoogleDeletionStartInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=200,body=GoogleStartResponse),(status=400,description="Confirmation/closed input rejected"),(status=401,description="Current provider session required"),(status=403,description="Origin rejected"),(status=413,description="Body too large"),(status=415,description="JSON required"),(status=429,description="Admission denied"),(status=503,description="Provider/storage unavailable"),(status=504,description="Boundary timeout")))]
pub(super) async fn start(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<GoogleDeletionStartInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    confirm(&input.confirmation)?;
    COOKIES.require_absent(&headers)?;
    let purpose = binding::deletion_purpose(&state, &headers).await?;
    let browser = Secret::generate()?;
    let source = source_key(source);
    let start = state
        .services
        .deletion_authorization
        .begin(&OAuthIntent {
            browser: &browser,
            source: &source,
            purpose,
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

#[utoipa::path(post,path="/v1/account/google-delete/finish",request_body=GoogleDeletionFinishInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Account deletion committed; session/proof cookies cleared"),(status=400,description="Confirmation/closed input rejected"),(status=401,description="Binding/freshness/claim rejection or bound provider denial"),(status=403,description="Origin rejected"),(status=413,description="Body too large"),(status=415,description="JSON required"),(status=429,description="Admission denied"),(status=503,description="Provider/profile/storage unavailable"),(status=504,description="Boundary timeout")))]
pub(super) async fn finish(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<GoogleDeletionFinishInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    confirm(&input.confirmation)?;
    let purpose = binding::deletion_purpose(&state, &headers).await?;
    let (transaction, returned) = binding::callback(&input.query, &COOKIES, &headers)?;
    let result = complete(&state, &source_key(source), purpose, transaction, returned).await;
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
    state: &WebState,
    source: &str,
    purpose: OAuthPurpose,
    transaction: Transaction,
    returned: GoogleAuthorizationResponse,
) -> auth_core::Result<()> {
    let completion = state
        .services
        .deletion_authorization
        .finish(
            &OAuthIntent {
                browser: &transaction.browser,
                source,
                purpose,
            },
            &transaction.state,
            transaction.proof,
            state.services.policy.configuration().redirect(),
            returned,
        )
        .await?;
    state
        .services
        .deletion
        .finish(state.services.policy.map(binding::verified(completion)?)?)
        .await
}

#[utoipa::path(post,path="/v1/account/google-delete/cancel",request_body=GoogleEmptyInput,
    params(("Origin"=String,Header),("Cookie"=String,Header)),
    responses((status=204,description="Bound pending deletion cancelled; current session retained"),(status=400,description="Closed input rejected"),(status=401,description="Binding rejected; own proof cookies cleared"),(status=403,description="Origin rejected"),(status=413,description="Body too large"),(status=415,description="JSON required"),(status=429,description="Admission denied"),(status=503,description="Storage unavailable; own proof cookies cleared"),(status=504,description="Boundary timeout")))]
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
    let purpose = binding::deletion_purpose(state, headers).await?;
    state
        .services
        .deletion_authorization
        .cancel(
            &OAuthIntent {
                browser: &transaction.browser,
                source,
                purpose,
            },
            &transaction.state,
            &transaction.proof,
        )
        .await
}
