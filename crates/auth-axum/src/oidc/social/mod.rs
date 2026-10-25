mod actor;
mod apple;
mod contract;
mod google;
mod pages;
mod routing;
mod services;
mod types;
mod unlink;

pub use contract::social_web_openapi;
pub use routing::experimental_social_web_router;
pub use services::SocialWebServices;

// Only trusted explicit router composition constructs this presentation marker.
// It confers no authentication or permission to consume a provider proof.
#[derive(Clone, Copy)]
pub(in crate::oidc) struct SocialLinkingSelected;

pub(in crate::oidc) use pages::google_return;
