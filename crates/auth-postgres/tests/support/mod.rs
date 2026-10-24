#[cfg(feature = "issuer-native-refresh")]
pub(crate) mod issuer_native_families;
pub(crate) mod legacy;
#[cfg(feature = "issuer-codes")]
pub(crate) mod legacy_attribution;
#[cfg(feature = "oauth-transactions")]
pub(crate) mod legacy_oauth;
#[cfg(any(feature = "saml-identities", feature = "google"))]
#[path = "../../../../tests/support/postgres/observation.rs"]
pub(crate) mod observation;
pub(crate) mod schema;

use auth_core::{Repository, Secret};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) async fn realm(pool: PgPool) -> (Postgres, Uuid) {
    let store = Postgres::new(pool);
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    (store, realm)
}
pub(crate) async fn challenge(store: &Postgres, realm: Uuid, email: &str) -> (Secret, Secret) {
    let token = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    store
        .begin_email(realm, email, token.verifier(), browser.verifier(), [1; 32])
        .await
        .unwrap();
    (token, browser)
}
pub(crate) async fn signed_in(store: &Postgres, realm: Uuid, email: &str) -> Secret {
    let (token, browser) = challenge(store, realm, email).await;
    let session = Secret::generate().unwrap();
    store
        .finish_email(
            realm,
            token.verifier(),
            browser.verifier(),
            session.verifier(),
        )
        .await
        .unwrap();
    session
}
pub(crate) async fn reset_proof(store: &Postgres, realm: Uuid, email: &str) -> (Secret, Secret) {
    let token = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    store
        .begin_password_reset(realm, email, token.verifier(), browser.verifier())
        .await
        .unwrap();
    (token, browser)
}

#[cfg(all(
    feature = "issuer-clients",
    not(any(feature = "saml-identities", feature = "google"))
))]
#[path = "../../../../tests/support/postgres/locks.rs"]
pub(crate) mod lock_observation;
#[cfg(all(
    feature = "issuer-clients",
    any(feature = "saml-identities", feature = "google")
))]
pub(crate) use observation as lock_observation;

#[cfg(feature = "issuer-signing")]
pub(crate) mod issuer_tokens;

#[cfg(feature = "issuer-native-refresh")]
pub(crate) mod issuer_native_consumers;
