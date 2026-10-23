use auth_core::IssuerTokenError;
use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

pub(super) enum TokenHttpError {
    InvalidRequest(StatusCode),
    InvalidClient,
    UnsupportedGrant,
    Core(IssuerTokenError),
}
#[derive(Serialize, ToSchema)]
pub(super) struct TokenErrorResponse {
    pub error: &'static str,
}
impl From<IssuerTokenError> for TokenHttpError {
    fn from(error: IssuerTokenError) -> Self {
        Self::Core(error)
    }
}
impl IntoResponse for TokenHttpError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::InvalidRequest(status) => (status, "invalid_request"),
            Self::InvalidClient | Self::Core(IssuerTokenError::InvalidClient) => {
                (StatusCode::UNAUTHORIZED, "invalid_client")
            }
            Self::UnsupportedGrant => (StatusCode::BAD_REQUEST, "unsupported_grant_type"),
            Self::Core(IssuerTokenError::InvalidGrant) => {
                (StatusCode::BAD_REQUEST, "invalid_grant")
            }
            Self::Core(IssuerTokenError::RateLimited) => {
                (StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable")
            }
            Self::Core(IssuerTokenError::Unavailable) => {
                (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
            }
        };
        let mut response = (status, Json(TokenErrorResponse { error })).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"easy-auth\""),
            );
        }
        response
    }
}
pub(super) fn invalid() -> TokenHttpError {
    TokenHttpError::InvalidRequest(StatusCode::BAD_REQUEST)
}
