mod authentication;
mod authorization;
mod flow;
mod request;
mod response;

pub use authentication::{OidcClientAuthentication, OidcClientSecret};
pub use authorization::OidcAuthorizationUrl;
pub use flow::{OidcCodeExchange, OidcTokenHttp};
pub use request::{OidcAuthorizationCode, OidcTokenRequest};
pub use response::OidcTokenResponse;

#[cfg(feature = "oidc-client")]
pub(in crate::oidc) use request::validate_endpoint as validate_token_endpoint;

#[cfg(feature = "oidc-client")]
pub(in crate::oidc) use authorization::validate_endpoint as validate_authorization_endpoint;
