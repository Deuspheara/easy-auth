use super::super::super::signed_idp;
use super::setup::{Fixture, counts};
use auth_core::{Error, SamlAccountDeletion, SamlDeletionVerifier, SamlVerifiedDeletion};
use saml_rs::{RespondSso, SamlInstant};
use sqlx::PgPool;

async fn prior_authentication(f: &Fixture, age_seconds: i64) -> SamlVerifiedDeletion {
    let start = f.requests.start(&f.current).await.unwrap();
    let instant = SamlInstant::try_new(saml_rs::entity::iso8601_offset(-age_seconds)).unwrap();
    let expected: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM $1::text::timestamptz)*1000000)::bigint")
            .bind(instant.as_str())
            .fetch_one(&f.source.pool)
            .await
            .unwrap();
    let input = signed_idp::response_with(
        &f.source,
        &start,
        "normal",
        RespondSso::post()
            .sign_response()
            .apply_web_browser_sso_generation_rules()
            .authentication_instant(instant),
    );
    let prepared = f
        .requests
        .prepare_response(
            &f.current,
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    let proof = SamlDeletionVerifier::new(f.policy.clone(), f.source.store.clone())
        .unwrap()
        .verify(prepared, input)
        .await
        .unwrap();
    assert_eq!(proof.assertion().authenticated_at_us(), expected);
    assert_eq!(proof.fresh_until_us(), expected + 300 * 1_000_000);
    proof
}

#[sqlx::test(migrations = "./migrations")]
async fn newly_issued_signed_response_with_old_authentication_cannot_erase_account(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let proof = prior_authentication(&f, 600).await;
    let before = counts(&f).await;
    assert_eq!(before, (1, 1, 1, 2, 1, 0));
    assert!(matches!(
        SamlAccountDeletion::new(f.source.store.clone())
            .finish(proof)
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(counts(&f).await, before);
}

#[sqlx::test(migrations = "./migrations")]
async fn genuinely_recent_established_authentication_still_permits_bound_deletion(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let proof = prior_authentication(&f, 120).await;
    SamlAccountDeletion::new(f.source.store.clone())
        .finish(proof)
        .await
        .unwrap();
    assert_eq!(counts(&f).await, (0, 0, 0, 4, 2, 0));
}
