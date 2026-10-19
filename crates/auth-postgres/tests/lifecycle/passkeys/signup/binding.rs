use super::*;
use auth_core::{Error, PasskeyAuthenticationRepository, PasskeyAuthenticationRequest};

#[sqlx::test(migrations = "./migrations")]
async fn stages_browser_realm_rp_and_existing_authentication_cannot_be_confused(pool: PgPool) {
    let mut f = Signup::new(pool).await;
    let (id, response) = f.registration().await;
    let other_browser = Secret::generate().unwrap();
    assert!(matches!(
        f.flow
            .finish_registration(&other_browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    let mut request = f.request(id);
    request.realm = Uuid::new_v4();
    f.store.ensure_realm(request.realm).await.unwrap();
    assert!(matches!(
        f.store
            .load_signup_registration(&request, f.service.rp_id())
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.store
            .load_signup_registration(&f.request(id), "other.example.com")
            .await,
        Err(Error::Unauthorized)
    ));
    let pending = f
        .flow
        .finish_registration(&f.browser, SOURCE, id, &response)
        .await
        .unwrap();
    assert!(matches!(
        f.flow
            .finish_registration(&f.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.store
            .load_signup_registration(&f.request(id), f.service.rp_id())
            .await,
        Err(Error::Unauthorized)
    ));
    let normal = PasskeyAuthenticationRequest {
        realm: f.realm,
        transaction: id,
        browser: f.browser.verifier(),
        source: [1; 32],
    };
    assert!(matches!(
        f.store
            .load_authentication(&normal, f.service.rp_id(), response.raw_id.as_slice())
            .await,
        Err(Error::Unauthorized)
    ));
    let response = f
        .token
        .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
        .unwrap();
    assert!(matches!(
        f.flow.finish(&other_browser, SOURCE, id, &response).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
    assert!(
        f.flow
            .finish(&f.browser, SOURCE, id, &response)
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn proof_cannot_complete_another_signup_or_overwrite_a_changed_candidate(pool: PgPool) {
    let mut f = Signup::new(pool).await;
    let (a, response) = f.assertion().await;
    let (b, _) = f.assertion().await;
    let proof = f.proof(a, &response).await;
    assert!(matches!(
        f.store.commit_signup(&f.request(b), proof, [1; 32]).await,
        Err(Error::Unauthorized)
    ));
    let proof = f.proof(a, &response).await;
    let original = proof.expected_credential_for_database().to_vec();
    let changed = [&b" "[..], original.as_slice()].concat();
    sqlx::query("UPDATE auth_passkey_signups SET candidate=$2 WHERE id=$1")
        .bind(a)
        .bind(changed)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.store.commit_signup(&f.request(a), proof, [2; 32]).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
    sqlx::query("UPDATE auth_passkey_signups SET candidate=$2 WHERE id=$1")
        .bind(a)
        .bind(original)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        f.flow
            .finish(&f.browser, SOURCE, a, &response)
            .await
            .is_ok()
    );
}
