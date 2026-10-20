use auth_core::Error;
use easy_auth_server::{GoogleDesktopError, GoogleDesktopLaunchError, GoogleDesktopSignInError};

pub(super) fn local(error: Error) -> &'static str {
    match error {
        Error::Unauthorized => "local_authority_rejected",
        Error::Unavailable => "local_storage_unavailable",
        Error::RateLimited => "local_rate_limited",
        Error::InvalidInput => "local_invalid_input",
    }
}

pub(super) fn operation(error: GoogleDesktopSignInError) -> &'static str {
    match error {
        GoogleDesktopSignInError::Core(Error::Unauthorized) => "provider_or_binding_rejected",
        GoogleDesktopSignInError::Core(Error::Unavailable) => "provider_or_storage_unavailable",
        GoogleDesktopSignInError::Core(Error::RateLimited) => "operation_rate_limited",
        GoogleDesktopSignInError::Core(Error::InvalidInput) => "operation_invalid_input",
        GoogleDesktopSignInError::Transport(GoogleDesktopError::InvalidInput) => {
            "return_invalid_input"
        }
        GoogleDesktopSignInError::Transport(GoogleDesktopError::Unavailable) => {
            "return_unavailable"
        }
        GoogleDesktopSignInError::Transport(GoogleDesktopError::Expired) => "return_expired",
        GoogleDesktopSignInError::Transport(GoogleDesktopError::Cancelled) => "return_cancelled",
        GoogleDesktopSignInError::Transport(GoogleDesktopError::RequestLimit) => {
            "return_request_limit"
        }
        GoogleDesktopSignInError::Launch(GoogleDesktopLaunchError::Unavailable) => {
            "launcher_unavailable"
        }
        GoogleDesktopSignInError::Launch(GoogleDesktopLaunchError::TimedOut) => {
            "launcher_timed_out"
        }
        GoogleDesktopSignInError::Launch(GoogleDesktopLaunchError::CleanupUnavailable) => {
            "launcher_cleanup_unconfirmed"
        }
    }
}
