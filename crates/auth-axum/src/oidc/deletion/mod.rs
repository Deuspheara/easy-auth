mod contract;
mod handlers;
mod pages;
mod routing;
mod types;

pub use contract::oidc_account_deletion_openapi;
pub use routing::{OidcAccountDeletionServices, experimental_oidc_account_deletion_router};
