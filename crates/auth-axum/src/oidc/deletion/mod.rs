mod contract;
mod handlers;
mod pages;
mod routing;
mod types;

pub use contract::oidc_account_deletion_openapi;
#[cfg(feature = "oidc-web")]
pub(super) use pages::callback_page;
#[cfg(feature = "oidc-web")]
pub(super) use routing::routes;
pub use routing::{OidcAccountDeletionServices, experimental_oidc_account_deletion_router};
