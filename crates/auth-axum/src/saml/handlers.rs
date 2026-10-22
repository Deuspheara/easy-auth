use super::{cookies, routing::WebState, types::*};
use crate::{browser::require_anonymous, error::ApiError, handlers::sessions::session_response};
use auth_core::{Error, SamlPostResponse, Secret};
use axum::{
    Json,
    extract::{
        Form, Query, State,
        rejection::{FormRejection, JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

type ClosedQuery = Result<Query<NoQuery>, QueryRejection>;

#[utoipa::path(post,path="/v1/saml/sign-in/start",request_body=SamlEmptyInput,params(("Origin"=String,Header),("Cookie"=Option<String>,Header)),responses((status=200,body=SamlStartResponse),(status=400),(status=401),(status=403),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn start(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<SamlEmptyInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(_) = body?;
    require_anonymous(&state.base.browser, &headers)?;
    cookies::SIGN_IN.require_absent(&headers)?;
    let start = state.services.transactions.start().await?;
    let mut response = Json(SamlStartResponse {
        authorization_url: start.authorization_url().to_owned(),
    })
    .into_response();
    cookies::SIGN_IN.set(&mut response, &state.base.browser, &start);
    Ok(response)
}

#[utoipa::path(post,path="/v1/saml/sign-in/finish",request_body(content=SamlPostDelivery,content_type="application/x-www-form-urlencoded"),params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=204),(status=400),(status=401),(status=403),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(super) async fn finish(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Form<SamlPostDelivery>, FormRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Form(input) = body.map_err(super::delivery::form_error)?;
    let result = complete(&state, &headers, input).await;
    let mut response = match result {
        Ok(session) => session_response(&state.base, &session),
        Err(error) => ApiError::from(error).into_response(),
    };
    cookies::SIGN_IN.clear(&mut response, &state.base.browser);
    Ok(response)
}
async fn complete(
    state: &WebState,
    headers: &HeaderMap,
    input: SamlPostDelivery,
) -> auth_core::Result<Secret> {
    require_anonymous(&state.base.browser, headers)?;
    let transaction = cookies::SIGN_IN.read(headers)?;
    let returned = Secret::parse(input.relay)?;
    if returned.verifier() != transaction.relay.verifier() {
        return Err(Error::Unauthorized);
    }
    let input = SamlPostResponse::parse(input.response)?;
    let prepared = state
        .services
        .transactions
        .prepare_response(
            &transaction.request,
            &transaction.relay,
            &transaction.browser,
        )
        .await?;
    let verified = state.services.verifier.verify(prepared, input).await?;
    let (_, session) = state
        .services
        .sign_in
        .finish(state.services.policy.map(verified)?)
        .await?;
    Ok(session)
}

#[utoipa::path(post,path="/v1/saml/sign-in/cancel",request_body=SamlEmptyInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=204),(status=400),(status=401),(status=403),(status=413),(status=415),(status=503),(status=504)))]
pub(super) async fn cancel(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<SamlEmptyInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(_) = body?;
    let result = async {
        let transaction = cookies::SIGN_IN.read(&headers)?;
        state
            .services
            .transactions
            .cancel(
                &transaction.request,
                &transaction.relay,
                &transaction.browser,
            )
            .await
    }
    .await;
    let mut response = match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => ApiError::from(error).into_response(),
    };
    cookies::SIGN_IN.clear(&mut response, &state.base.browser);
    Ok(response)
}
#[utoipa::path(get,path="/saml/metadata",responses((status=200,body=String,content_type="application/samlmetadata+xml"),(status=400)))]
pub(super) async fn metadata(
    State(state): State<WebState>,
    query: ClosedQuery,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    Ok((
        [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
        state.services.policy.registration().metadata_xml(),
    )
        .into_response())
}
