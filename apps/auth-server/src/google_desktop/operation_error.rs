use super::GoogleDesktopError;
use std::fmt;

/// Finite launcher failures. No command, URL, OS message or provider detail retained.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GoogleDesktopLaunchError {
    Unavailable,
    TimedOut,
    CleanupUnavailable,
}
impl fmt::Display for GoogleDesktopLaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "system browser launcher unavailable",
            Self::TimedOut => "system browser launcher timed out",
            Self::CleanupUnavailable => "system browser launcher cleanup unconfirmed",
        })
    }
}
impl std::error::Error for GoogleDesktopLaunchError {}

/// Transport/launch failures are distinct from provider verification and storage.
#[derive(Debug)]
pub enum GoogleDesktopSignInError {
    Core(auth_core::Error),
    Transport(GoogleDesktopError),
    Launch(GoogleDesktopLaunchError),
}
impl fmt::Display for GoogleDesktopSignInError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(value) => value.fmt(f),
            Self::Transport(value) => value.fmt(f),
            Self::Launch(value) => value.fmt(f),
        }
    }
}
impl std::error::Error for GoogleDesktopSignInError {}
impl From<auth_core::Error> for GoogleDesktopSignInError {
    fn from(value: auth_core::Error) -> Self {
        Self::Core(value)
    }
}
impl From<GoogleDesktopError> for GoogleDesktopSignInError {
    fn from(value: GoogleDesktopError) -> Self {
        Self::Transport(value)
    }
}
impl From<GoogleDesktopLaunchError> for GoogleDesktopSignInError {
    fn from(value: GoogleDesktopLaunchError) -> Self {
        Self::Launch(value)
    }
}
