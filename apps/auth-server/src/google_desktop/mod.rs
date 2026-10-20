mod callback;
mod http;
#[cfg(feature = "google-desktop-launch")]
mod launch;
mod listener;
#[cfg(feature = "google-desktop-launch")]
mod operation;
#[cfg(feature = "google-desktop-launch")]
mod operation_error;
#[cfg(test)]
#[path = "../../../../tests/support/google/socket.rs"]
mod test_socket;
#[cfg(test)]
mod tests;

pub use callback::{GoogleDesktopCallback, GoogleDesktopError};
pub use listener::GoogleDesktopListener;
#[cfg(feature = "google-desktop-launch")]
pub use operation::GoogleDesktopSignIn;
#[cfg(feature = "google-desktop-launch")]
pub use operation_error::{GoogleDesktopLaunchError, GoogleDesktopSignInError};
