mod atomicity;
mod authorization;
mod binding;
mod callback;
mod lifecycle;
#[path = "../../../../../../tests/support/google/provider.rs"]
mod provider;
mod session_age;
mod setup;
use crate::support::observation as waits;
