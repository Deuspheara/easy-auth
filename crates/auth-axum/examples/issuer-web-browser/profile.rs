//! Owned application composition; never production provisioning or a signer.
use super::{FixtureResult, mail::Mail};
use auth_core::{Auth, IssuerAuthority, IssuerClientRegistration, IssuerSigningKey};
use auth_postgres::Postgres;
use axum::Router;
use easy_auth_axum::{BrowserConfig, IssuerWebServices, experimental_issuer_web_router};
use std::sync::Arc;
use uuid::Uuid;

pub(super) async fn application(
    realm: Uuid,
    origin: &str,
    authority: IssuerAuthority,
    store: Arc<Postgres>,
    key: Arc<IssuerSigningKey>,
    mail: Arc<Mail>,
) -> FixtureResult<(Router, Uuid)> {
    let native = match std::env::var("EASY_AUTH_OWNED_ISSUER_NATIVE") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "1" => true,
        _ => return Err("invalid owned issuer profile".into()),
    };
    if native {
        #[cfg(feature = "issuer-native-web")]
        return native_application(realm, origin, authority, store, key, mail).await;
        #[cfg(not(feature = "issuer-native-web"))]
        return Err("owned native feature required".into());
    }
    let client = store
        .configure_issuer_client(&IssuerClientRegistration::public(
            realm,
            Uuid::new_v4(),
            &["https://client.example/callback"],
        )?)
        .await?;
    let app = experimental_issuer_web_router(
        Auth::new(realm, store.clone(), mail),
        BrowserConfig::new(origin, false)?,
        IssuerWebServices::new(authority, store.clone(), store, vec![key])?,
    )?;
    Ok((app, client.client()))
}

#[cfg(feature = "issuer-native-web")]
async fn native_application(
    realm: Uuid,
    origin: &str,
    authority: IssuerAuthority,
    store: Arc<Postgres>,
    key: Arc<IssuerSigningKey>,
    mail: Arc<Mail>,
) -> FixtureResult<(Router, Uuid)> {
    use auth_core::IssuerNativeRefreshPolicy;
    use easy_auth_axum::{IssuerNativeWebServices, experimental_issuer_native_web_router};
    let client = store
        .configure_issuer_client(&IssuerClientRegistration::public_native_refresh_loopback(
            realm,
            Uuid::new_v4(),
            &["http://127.0.0.1/callback"],
        )?)
        .await?;
    let policy = store
        .configure_issuer_native_refresh_policy(&IssuerNativeRefreshPolicy::new(
            authority.clone(),
            client.clone(),
            3600,
            600,
        )?)
        .await?;
    store.enable_issuer_native_refresh_policy(&policy).await?;
    // Reuse the original server's ordinary key. No additional signer, verified
    // proof constructor or fixture credential is introduced by this mode.
    let base = IssuerWebServices::new(authority, store.clone(), store.clone(), vec![key])?;
    let services = IssuerNativeWebServices::new(base, store.clone(), store.clone(), store.clone());
    let app = experimental_issuer_native_web_router(
        Auth::new(realm, store, mail),
        BrowserConfig::new(origin, false)?,
        services,
    )?;
    Ok((app, client.client()))
}
