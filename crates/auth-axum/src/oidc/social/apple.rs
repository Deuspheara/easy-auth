use super::{
    actor::{self, Source},
    routing::WebState,
    types::*,
};
use crate::{
    error::ApiError,
    handlers::source_key,
    oidc::cookies::{APPLE_LINK_COOKIES as COOKIES, Transaction},
};
use auth_core::{
    AppleAuthorizationCompletion, AppleAuthorizationResponse, Error, OAuthIntent, Secret,
};
use axum::{
    Json,
    extract::{
        Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

#[utoipa::path(post,path="/v1/account/apple-link/start",request_body=SocialLinkStartInput,
    responses((status=200,body=SocialLinkStartResponse),(status=400),(status=401),(status=403),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn start(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<SocialLinkStartInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    confirm(&input.confirmation, "link this account")?;
    let (_, purpose) = actor::current(&state.base, &headers, Some(input.expected_owner)).await?;
    COOKIES.require_absent(&headers)?;
    let browser = Secret::generate()?;
    let source = source_key(source);
    let start = state
        .services
        .apple_link
        .begin(&OAuthIntent {
            browser: &browser,
            source: &source,
            purpose,
        })
        .await?;
    let mut response = Json(SocialLinkStartResponse {
        authorization_url: start
            .request
            .web_url()
            .ok_or(Error::Unavailable)?
            .to_owned(),
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

#[utoipa::path(post,path="/v1/account/apple-link/finish",request_body=AppleLinkFinishInput,
    responses((status=204,description="Identity linked to original owner; current session retained"),(status=400),(status=401),(status=403),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn finish(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<AppleLinkFinishInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    confirm(&input.confirmation, "link this account")?;
    let (current, purpose) = actor::current(&state.base, &headers, None).await?;
    let transaction = COOKIES.read(&headers)?;
    let returned = AppleAuthorizationResponse::parse(&input.response)?;
    if returned.state().verifier() != transaction.state.verifier() {
        return Err(Error::Unauthorized.into());
    }
    let result = complete(
        &state,
        &source_key(source),
        transaction,
        purpose,
        &current,
        returned,
    )
    .await;
    let mut response = match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => ApiError::from(error).into_response(),
    };
    COOKIES.clear(&mut response, &state.base.browser);
    Ok(response)
}
async fn complete(
    state: &WebState,
    source: &str,
    transaction: Transaction,
    purpose: auth_core::OAuthPurpose,
    current: &Secret,
    returned: AppleAuthorizationResponse,
) -> auth_core::Result<()> {
    let completion = state
        .services
        .apple_link
        .finish(
            &OAuthIntent {
                browser: &transaction.browser,
                source,
                purpose,
            },
            &transaction.state,
            transaction.proof,
            state.services.apple.policy().configuration().redirect(),
            returned,
        )
        .await?;
    let identity = match completion {
        AppleAuthorizationCompletion::Verified { identity, .. } => *identity,
        AppleAuthorizationCompletion::Denied => return Err(Error::Unauthorized),
        AppleAuthorizationCompletion::ProviderFailure => return Err(Error::Unavailable),
    };
    state
        .services
        .linking
        .finish(state.services.apple.policy().map(identity)?, current)
        .await?;
    Ok(())
}

#[utoipa::path(post,path="/v1/account/apple-link/cancel",request_body=SocialLinkCancelInput,
    responses((status=204,description="Original bound link cancelled; session retained"),(status=400),(status=401),(status=403),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn cancel(
    State(state): State<WebState>,
    query: Result<Query<NoQuery>, QueryRejection>,
    headers: HeaderMap,
    source: Source,
    body: Result<Json<SocialLinkCancelInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    let (_, purpose) = actor::current(&state.base, &headers, None).await?;
    let transaction = actor::cancel_transaction(&COOKIES, &headers, input.state)?;
    let source = source_key(source);
    let result = state
        .services
        .apple_link
        .cancel(
            &OAuthIntent {
                browser: &transaction.browser,
                source: &source,
                purpose,
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
