mod contract;
pub(crate) mod cookies;
mod handlers;
mod pages;
mod routing;
mod types;

pub use contract::issuer_consent_openapi;
pub use routing::experimental_issuer_consent_router;

#[cfg(any(feature = "issuer-web", feature = "issuer-native-consent-web"))]
pub(crate) use routing::attach;
