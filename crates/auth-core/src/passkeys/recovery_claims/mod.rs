mod flow;
mod repository;
mod types;

pub use flow::PasskeyRecoveryClaims;
pub use repository::{
    PasskeyRecoveryClaimRepository, PasskeyRecoveryClaimRequest, PasskeyRecoveryCodeCancellation,
    PasskeyRecoveryKeyCancellation,
};
pub use types::PasskeyRecoveryClaimInfo;

pub const PASSKEY_RECOVERY_DELAY_SECONDS: i32 = 24 * 60 * 60;
pub const PASSKEY_RECOVERY_LIFETIME_SECONDS: i32 = 7 * 24 * 60 * 60;
