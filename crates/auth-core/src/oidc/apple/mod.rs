mod authorization;
mod callback;
mod exchange;
mod flow;
#[cfg(feature = "oidc-linking")]
mod linking;
#[cfg(feature = "oidc-linking")]
pub use linking::AppleIdentityLinkAuthorization;
mod key;
mod nonce;
mod profile;
mod secret;

pub use authorization::AppleAuthorizationRequest;
pub use callback::{AppleAuthorizationOutcome, AppleAuthorizationResponse};
pub use exchange::{AppleClientType, AppleCodeExchange};
pub use flow::{AppleAuthorization, AppleAuthorizationCompletion, AppleAuthorizationStart};
pub use nonce::AppleNonceEncoding;
pub use profile::AppleInitialProfile;
pub use secret::{AppleClientSecret, AppleClientSecretSigner};

#[cfg(feature = "apple-grants")]
mod grants;
#[cfg(feature = "apple-grants")]
pub use grants::{AppleGrantBinding, AppleGrantEnvelope, AppleGrantKey, AppleGrantVault};

#[cfg(feature = "apple-grants")]
pub use grants::{
    AppleGrantAuthorization, AppleGrantAuthorizationCompletion, AppleGrantCapture,
    AppleGrantLinking, AppleGrantRepository, AppleGrantSignIn, AppleMappedGrant,
    AppleVerifiedGrant,
};
