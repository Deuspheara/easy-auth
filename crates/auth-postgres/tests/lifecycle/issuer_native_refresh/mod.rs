mod authorization;
mod configuration;
mod consent;
mod families;
mod isolation;
mod ordering;
mod upgrade;

use auth_core::{Error, IssuerAuthority, IssuerClientRegistration, IssuerNativeRefreshPolicy};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use uuid::Uuid;

async fn setup(pool: &PgPool) -> (Postgres, IssuerNativeRefreshPolicy) {
    let (store, realm) = crate::support::realm(pool.clone()).await;
    let client = store
        .configure_issuer_client(
            &IssuerClientRegistration::public_native_refresh_loopback(
                realm,
                Uuid::new_v4(),
                &["http://127.0.0.1:41001/cb"],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let authority = IssuerAuthority::new(realm, "https://issuer.example").unwrap();
    let policy = IssuerNativeRefreshPolicy::new(authority, client, 86400, 3600).unwrap();
    (store, policy)
}
