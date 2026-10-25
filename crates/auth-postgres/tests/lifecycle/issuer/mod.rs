mod authentication;
mod configuration;
mod loading;
mod native;
mod native_lifecycle;
mod native_ordering;
#[cfg(not(feature = "issuer-native-refresh"))]
mod native_refresh_unavailable;
mod native_upgrade;
mod ordering;
mod subjects;
mod upgrade;

use auth_core::{IssuerClientRegistration, Repository};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use uuid::Uuid;

async fn setup(pool: &PgPool) -> (Postgres, Uuid, Uuid) {
    let (store, realm) = crate::support::realm(pool.clone()).await;
    let session = crate::support::signed_in(&store, realm, "owner@example.test").await;
    let user = store.authenticate(realm, session.verifier()).await.unwrap();
    (store, realm, user.id)
}
fn public(realm: Uuid, client: Uuid, redirect: &str) -> IssuerClientRegistration {
    IssuerClientRegistration::public(realm, client, &[redirect]).unwrap()
}
fn native(realm: Uuid, client: Uuid, redirect: &str) -> IssuerClientRegistration {
    IssuerClientRegistration::public_native_loopback(realm, client, &[redirect]).unwrap()
}
