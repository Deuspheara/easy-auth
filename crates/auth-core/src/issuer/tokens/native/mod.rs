//! Explicit native offline configuration, separate from browser-session authority.
mod policy;
#[cfg(test)]
mod tests;

pub use policy::{
    IssuerNativeRefreshPolicy, MAX_NATIVE_REFRESH_IDLE_SECONDS, MAX_NATIVE_REFRESH_LIFETIME_SECONDS,
};
