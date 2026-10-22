mod callback;
mod contract;
mod handlers;
mod pages;
mod routing;
mod types;

pub use contract::oidc_web_openapi;
pub use routing::{OidcWebServices, oidc_web_router};

#[cfg(feature = "saml-web")]
pub(crate) use routing::{attach, clear_proofs};
