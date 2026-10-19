use super::*;
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn simultaneous_last_key_removals_have_one_winner(pool: PgPool) {
    let f = Management::new(pool.clone(), true).await;
    let (id, mut token) = f.add_key("Spare").await;
    let second_session = f.sign_in(&mut token).await;
    let first = f.keys().await.into_iter().find(|key| key.id != id).unwrap();
    let second = f.key(id).await;
    let (a, b) = tokio::join!(
        f.flow.remove(&f.session, SOURCE, first.id, first.version),
        f.flow
            .remove(&second_session, SOURCE, second.id, second.version),
    );
    assert!(matches!(
        (&a, &b),
        (Ok(()), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(()))
    ));
    let (keys, audits): (i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_passkeys WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_removed')")
        .bind(f.fixture.realm).fetch_one(&pool).await.unwrap();
    assert_eq!((keys, audits), (1, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn competing_renames_require_the_exact_current_management_version(pool: PgPool) {
    let f = Management::new(pool, false).await;
    let key = f.keys().await.remove(0);
    let (a, b) = tokio::join!(
        f.flow
            .rename(&f.session, SOURCE, key.id, key.version, "First"),
        f.flow
            .rename(&f.session, SOURCE, key.id, key.version, "Second"),
    );
    assert!(matches!(
        (&a, &b),
        (Ok(_), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(_))
    ));
    let current = f.key(key.id).await;
    let winner = a.or(b).unwrap();
    assert_eq!(current.version, winner);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_verified_assertion_cannot_issue_a_session_after_credential_removal(pool: PgPool) {
    use auth_core::{PasskeyAuthenticationRepository, PasskeyAuthenticationRequest};
    let f = Management::new(pool.clone(), true).await;
    let (id, mut token) = f.add_key("Key to remove").await;
    let signin = PasskeySignIn::new(
        f.fixture.realm,
        f.fixture.service.clone(),
        f.fixture.store.clone(),
    );
    let pending = signin
        .begin_account(f.owner, &f.fixture.browser, SOURCE)
        .await
        .unwrap();
    let response = token
        .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
        .unwrap();
    let request = PasskeyAuthenticationRequest {
        realm: f.fixture.realm,
        transaction: pending.transaction,
        browser: f.fixture.browser.verifier(),
        source: [1; 32],
    };
    let (state, credential) = f
        .fixture
        .store
        .load_authentication(
            &request,
            f.fixture.service.rp_id(),
            response.raw_id.as_slice(),
        )
        .await
        .unwrap();
    let proof = f
        .fixture
        .service
        .verify_authentication(&response, state, credential)
        .unwrap();
    let key = f.key(id).await;
    f.flow
        .remove(&f.session, SOURCE, key.id, key.version)
        .await
        .unwrap();
    let new = Secret::generate().unwrap();
    assert!(matches!(
        f.fixture
            .store
            .commit_authentication(&request, proof, new.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.fixture
            .store
            .authenticate(f.fixture.realm, new.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
}
