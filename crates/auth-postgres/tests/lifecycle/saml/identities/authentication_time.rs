use super::super::signed_idp;
use super::setup::{allow_jit, facts, fixture};
use auth_core::{Error, Repository, SamlResponseVerifier, SamlSignIn};
use saml_rs::{RespondSso, SamlInstant};
use sqlx::PgPool;

async fn prior_authentication(
    f: &super::super::setup::Fixture,
    age_seconds: i64,
) -> (auth_core::Result<auth_core::VerifiedSamlAssertion>, i64) {
    let authenticated =
        SamlInstant::try_new(saml_rs::entity::iso8601_offset(-age_seconds)).unwrap();
    let expected: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM $1::text::timestamptz)*1000000)::bigint")
            .bind(authenticated.as_str())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let start = f.flow.start().await.unwrap();
    let input = signed_idp::response_with(
        f,
        &start,
        "normal",
        RespondSso::post()
            .sign_response()
            .apply_web_browser_sso_generation_rules()
            .authentication_instant(authenticated),
    );
    let prepared = f
        .flow
        .prepare_response(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    let proof = SamlResponseVerifier::new(f.registration.clone(), f.store.clone())
        .unwrap()
        .verify(prepared, input)
        .await;
    (proof, expected)
}

#[sqlx::test(migrations = "./migrations")]
async fn new_response_preserves_old_authentication_and_cannot_extend_maximum_session_age(
    pool: PgPool,
) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let (proof, expected) = prior_authentication(&f, 600).await;
    let proof = proof.unwrap();
    assert_eq!(proof.authenticated_at_us(), expected);
    assert_eq!(
        proof.session_expires_at_us(),
        expected + 24 * 60 * 60 * 1_000_000
    );
    assert!(proof.expires_at_us() < proof.session_expires_at_us());
    let (user, bearer) = SamlSignIn::new(f.store.clone())
        .finish(policy.map(proof).unwrap())
        .await
        .unwrap();
    let stored: i64 = sqlx::query_scalar("SELECT (extract(epoch FROM authenticated_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
        .bind(user.realm_id).bind(bearer.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(stored, expected);
    f.store
        .authenticate(user.realm_id, bearer.verifier())
        .await
        .unwrap();

    assert!(matches!(
        prior_authentication(&f, 90_000).await.0,
        Err(Error::Unauthorized)
    ));
    assert_eq!(facts(&f).await, (1, 1, 1, 2, 1));
}
