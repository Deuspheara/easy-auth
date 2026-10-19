mod boundaries;
mod races;
mod waiting;

use super::*;
use auth_core::PasskeyRepository;

async fn prepare(
    f: &Fixture,
) -> (
    PasskeyEnrollmentRequest,
    Vec<u8>,
    auth_core::VerifiedPasskey,
) {
    let (id, response) = f.begin().await;
    let request = f.request(id);
    let state = f.store.load_enrollment(&request).await.unwrap();
    let encoded = state.encode_for_database().unwrap();
    let credential = f.service.verify_registration(&response, state).unwrap();
    (request, encoded, credential)
}

async fn first_key(f: &Fixture) -> SoftToken {
    let (id, response, token) = f.begin_with_token().await;
    f.enrollment
        .finish(&f.session, &f.browser, SOURCE, id, &response)
        .await
        .unwrap();
    token
}

async fn sign_in(f: &Fixture, token: &mut SoftToken) -> Secret {
    f.sign_in_with_key(token).await
}

async fn counts(pool: &PgPool, realm: Uuid) -> (i64, i64, i64) {
    sqlx::query_as("SELECT (SELECT count(*) FROM auth_passkeys WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_enrolled'),(SELECT count(*) FROM auth_passkey_enrollments WHERE realm_id=$1)")
        .bind(realm).fetch_one(pool).await.unwrap()
}
