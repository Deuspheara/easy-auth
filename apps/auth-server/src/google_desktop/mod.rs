mod callback;
mod http;
mod listener;
#[cfg(test)]
#[path = "../../../../tests/support/google/socket.rs"]
mod test_socket;
#[cfg(test)]
mod tests;

pub use callback::{GoogleDesktopCallback, GoogleDesktopError};
pub use listener::GoogleDesktopListener;
