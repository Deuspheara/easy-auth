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
