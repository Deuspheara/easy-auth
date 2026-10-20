#[cfg(all(feature = "google-desktop", feature = "oidc-identities"))]
#[path = "google_desktop/mod.rs"]
mod acceptance;
