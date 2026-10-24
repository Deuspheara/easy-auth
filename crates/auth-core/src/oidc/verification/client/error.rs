use crate::Error;

/// Finite client failures. Provider bodies, credentials and callback values are
/// deliberately absent; none of these errors is a local authentication result.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum OidcClientError {
    #[error("invalid client configuration")]
    Configuration,
    #[error("authorization response did not match the pending operation")]
    Callback,
    #[error("authorization was denied")]
    Denied,
    #[error("authorization operation expired")]
    Expired,
    #[error("client authentication was rejected")]
    InvalidClient,
    #[error("authorization grant was rejected")]
    InvalidGrant,
    #[error("token verification failed")]
    InvalidToken,
    #[error("invalid protocol response")]
    Protocol,
    #[error("client operation capacity exceeded")]
    RateLimited,
    #[error("client operation unavailable")]
    Unavailable,
}
pub type OidcClientResult<T> = std::result::Result<T, OidcClientError>;
pub(super) fn infrastructure(error: Error) -> OidcClientError {
    match error {
        Error::RateLimited => OidcClientError::RateLimited,
        _ => OidcClientError::Unavailable,
    }
}
