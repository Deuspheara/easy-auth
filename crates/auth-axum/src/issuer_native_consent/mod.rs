mod contract;
mod handlers;
mod pages;
mod routing;
mod types;

pub use contract::issuer_native_consent_openapi;
pub use routing::experimental_issuer_native_consent_router;

#[cfg(feature = "issuer-native-web")]
pub(crate) use routing::attach_with_pages;
