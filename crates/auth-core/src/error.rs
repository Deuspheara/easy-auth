use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid input")]
    InvalidInput,
    #[error("authentication required")]
    Unauthorized,
    #[error("too many requests")]
    RateLimited,
    #[error("authentication temporarily unavailable")]
    Unavailable,
}
pub type Result<T> = std::result::Result<T, Error>;
