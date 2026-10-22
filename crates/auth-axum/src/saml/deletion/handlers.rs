use super::types::{SamlDeletionConfirmation, SamlDeletionDelivery, confirm};
use crate::{
    browser::{clear_auth_cookies, read_cookie},
    error::ApiError,
    saml::{
        cookies,
        routing::WebState,
        types::{NoQuery, SamlEmptyInput, SamlStartResponse},
    },
};
use auth_core::{Error, SamlPostResponse, Secret};
use axum::{
    Json,
    extract::{
        Form, Query, State,
        rejection::{FormRejection, JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

type ClosedQuery = Result<Query<NoQuery>, QueryRejection>;

#[utoipa::path(post,path="/v1/saml/account-delete/start",operation_id="samlAccountDeletionStart",request_body=SamlDeletionConfirmation,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=200,body=SamlStartResponse),(status=400),(status=401),(status=403),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(in crate::saml) async fn start(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<SamlDeletionConfirmation>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(input) = body?;
    confirm(&input.confirmation)?;
    cookies::require_no_pending(&headers)?;
    let current = read_cookie(&headers, state.base.browser.session_name())?;
    let services = state.services.deletion.as_ref().ok_or(Error::Unavailable)?;
    let start = services.requests.start(&current).await?;
    let mut response = Json(SamlStartResponse {
        authorization_url: start.authorization_url().to_owned(),
    })
    .into_response();
    cookies::ACCOUNT_DELETION.set(&mut response, &state.base.browser, &start);
    Ok(response)
}

#[utoipa::path(post,path="/v1/saml/account-delete/finish",operation_id="samlAccountDeletionFinish",request_body(content=SamlDeletionDelivery,content_type="application/x-www-form-urlencoded"),params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=204,description="Atomic deletion committed; no session issued"),(status=400),(status=401),(status=403),(status=413),(status=415),(status=429),(status=503),(status=504)))]
pub(in crate::saml) async fn finish(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Form<SamlDeletionDelivery>, FormRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Form(input) = body.map_err(crate::saml::delivery::form_error)?;
    confirm(&input.confirmation)?;
    let transaction = cookies::ACCOUNT_DELETION.read(&headers)?;
    let returned = Secret::parse(input.relay)?;
    if returned.verifier() != transaction.relay.verifier() {
        // A stale/foreign response cannot clear a newer operation's cookies.
        return Err(Error::Unauthorized.into());
    }
    let result = complete(&state, &headers, transaction, input.response).await;
    Ok(match result {
        Ok(()) => clear_auth_cookies(&state.base.browser),
        Err(error) => {
            let mut response = ApiError::from(error).into_response();
            cookies::ACCOUNT_DELETION.clear(&mut response, &state.base.browser);
            response
        }
    })
}

async fn complete(
    state: &WebState,
    headers: &HeaderMap,
    transaction: cookies::Transaction,
    response: String,
) -> auth_core::Result<()> {
    let current = read_cookie(headers, state.base.browser.session_name())?;
    let input = SamlPostResponse::parse(response)?;
    let services = state.services.deletion.as_ref().ok_or(Error::Unavailable)?;
    let prepared = services
        .requests
        .prepare_response(
            &current,
            &transaction.request,
            &transaction.relay,
            &transaction.browser,
        )
        .await?;
    let proof = services.verifier.verify(prepared, input).await?;
    services.deletion.finish(proof).await
}

#[utoipa::path(post,path="/v1/saml/account-delete/cancel",operation_id="samlAccountDeletionCancel",request_body=SamlEmptyInput,params(("Origin"=String,Header),("Cookie"=String,Header)),responses((status=204,description="Bound pending deletion cancelled; account retained"),(status=400),(status=401),(status=403),(status=413),(status=415),(status=503),(status=504)))]
pub(in crate::saml) async fn cancel(
    State(state): State<WebState>,
    query: ClosedQuery,
    headers: HeaderMap,
    body: Result<Json<SamlEmptyInput>, JsonRejection>,
) -> Result<Response, ApiError> {
    query.map_err(|_| ApiError::Body(StatusCode::BAD_REQUEST))?;
    let Json(_) = body?;
    let result = async {
        let transaction = cookies::ACCOUNT_DELETION.read(&headers)?;
        let current = read_cookie(&headers, state.base.browser.session_name())?;
        let services = state.services.deletion.as_ref().ok_or(Error::Unavailable)?;
        services
            .requests
            .cancel(
                &current,
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
    cookies::ACCOUNT_DELETION.clear(&mut response, &state.base.browser);
    Ok(response)
}
