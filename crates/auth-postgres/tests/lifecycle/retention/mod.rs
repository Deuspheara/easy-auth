mod admission;
mod apple;
mod batching;
mod cancellation;
mod federation;
#[cfg(feature = "issuer-native-refresh")]
mod issuer;
mod notifications;
mod proofs;
mod replays;
mod sessions;

use auth_core::{RetentionHorizon, RetentionPolicy};

fn keeping() -> RetentionPolicy {
    RetentionPolicy::new(RetentionHorizon::keep(), RetentionHorizon::keep())
}
