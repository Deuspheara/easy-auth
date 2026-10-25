mod authorization;
mod completion;
mod contract;
mod delivery;
mod operation;
mod pages;
mod routing;
mod services;
mod signin;
mod types;

pub use contract::apple_web_openapi;
pub use routing::experimental_apple_web_router;
pub use services::AppleWebServices;

#[cfg(feature = "social-linking-web")]
pub(in crate::oidc) use routing::routes;
