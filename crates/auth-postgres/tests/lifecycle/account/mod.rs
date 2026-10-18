mod atomicity;
mod binding;
mod deletion;
mod email_change;

use auth_core::{Repository, Secret};
use easy_auth_postgres::Postgres;
use uuid::Uuid;

pub(super) async fn change_proofs(
    store: &Postgres,
    realm: Uuid,
    current: [u8; 32],
    email: &str,
) -> (Secret, Secret, Secret) {
    let old = Secret::generate().unwrap();
    let new = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    store
        .begin_email_change(
            realm,
            current,
            email,
            old.verifier(),
            new.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    (old, new, browser)
}
pub(super) async fn deletion_proof(
    store: &Postgres,
    realm: Uuid,
    current: [u8; 32],
) -> (Secret, Secret) {
    let token = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    store
        .begin_account_deletion(realm, current, token.verifier(), browser.verifier())
        .await
        .unwrap();
    (token, browser)
}
