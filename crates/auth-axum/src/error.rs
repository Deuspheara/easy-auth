use auth_core::Error;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;

pub(crate) enum ApiError {
    Core(Error),
    Body(StatusCode),
}
impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Body(status) = self {
            return (
                status,
                Json(ErrorResponse {
                    code: "invalid_body",
                }),
            )
                .into_response();
        }
        let Self::Core(error) = self else {
            unreachable!()
        };
        let (status, code) = match error {
            Error::InvalidInput => (StatusCode::BAD_REQUEST, "invalid_input"),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "authentication_required"),
            Error::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Error::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
        };
        (status, Json(json!({"code":code}))).into_response()
    }
}
impl From<axum::extract::rejection::JsonRejection> for ApiError {
    fn from(rejection: axum::extract::rejection::JsonRejection) -> Self {
        let status = match rejection.status() {
            StatusCode::PAYLOAD_TOO_LARGE => StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::UNSUPPORTED_MEDIA_TYPE => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            _ => StatusCode::BAD_REQUEST,
        };
        Self::Body(status)
    }
}
#[derive(Serialize, ToSchema)]
pub(crate) struct ErrorResponse {
    code: &'static str,
}
