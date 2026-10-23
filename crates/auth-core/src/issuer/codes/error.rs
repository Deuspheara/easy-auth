use crate::Error;

/// Finite token outcomes; client authentication, invalid grants and storage
/// failure stay distinct without retaining foreign diagnostics or secret input.
#[derive(Debug, thiserror::Error)]
pub enum IssuerTokenError {
    #[error("invalid client")]
    InvalidClient,
    #[error("invalid grant")]
    InvalidGrant,
    #[error("too many requests")]
    RateLimited,
    #[error("token service temporarily unavailable")]
    Unavailable,
}
impl IssuerTokenError {
    pub fn client(error: Error) -> Self {
        match error {
            Error::Unauthorized | Error::InvalidInput => Self::InvalidClient,
            other => other.into(),
        }
    }
}
impl From<Error> for IssuerTokenError {
    fn from(error: Error) -> Self {
        match error {
            Error::Unauthorized | Error::InvalidInput => Self::InvalidGrant,
            Error::RateLimited => Self::RateLimited,
            Error::Unavailable => Self::Unavailable,
        }
    }
}
pub type IssuerTokenResult<T> = std::result::Result<T, IssuerTokenError>;
