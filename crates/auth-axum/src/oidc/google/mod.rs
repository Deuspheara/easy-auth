mod binding;
mod callback;
mod contract;
mod deletion;
mod pages;
mod routing;
mod services;
mod signin;
mod types;

pub use contract::google_web_openapi;
pub use routing::experimental_google_web_router;
pub use services::GoogleWebServices;

#[cfg(feature = "social-linking-web")]
pub(in crate::oidc) use routing::routes;
