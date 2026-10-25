mod contract;
mod cookies;
mod deletion;
mod delivery;
mod handlers;
mod operation;
mod pages;
mod routing;
mod services;
mod types;

pub use contract::{saml_account_deletion_web_openapi, saml_web_openapi};
pub use deletion::SamlAccountDeletionWebServices;
pub use routing::experimental_saml_web_router;
pub use services::SamlWebServices;

#[cfg(any(feature = "oidc-web", feature = "issuer-native-web"))]
pub(crate) use routing::{attach, web_contract};
