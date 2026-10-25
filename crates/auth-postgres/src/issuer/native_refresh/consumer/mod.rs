//! Trusted consumer/audience provisioning and deterministic client lock order.
mod configuration;
mod locking;
pub(super) use locking::{lock_clients, lock_policy};
