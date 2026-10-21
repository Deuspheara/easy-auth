use super::setup::{Fixture, registration};
use auth_core::{
    Error, SamlBrowserProof, SamlRequestAdmission, SamlRequestRepository, SamlTransactions, Secret,
};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn start_persists_only_hashes_original_expiry_and_no_local_authority(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.flow.start().await.unwrap();
    let (relay, browser, lifetime): (Vec<u8>, Vec<u8>, f64) = sqlx::query_as(
        "SELECT relay_hash,browser_hash,extract(epoch FROM expires_at-created_at)::double precision FROM auth_saml_requests WHERE request_id=$1")
        .bind(start.request_id()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(relay, start.relay_state().verifier());
    assert_eq!(
        browser,
        Secret::parse(start.browser_proof().expose().to_owned())
            .unwrap()
            .verifier()
    );
    assert!(lifetime > 0.0 && lifetime <= 300.0);
    assert_eq!(format!("{start:?}"), "SamlStart([REDACTED])");
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_users")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_sessions")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!((users, sessions, f.pending().await), (0, 0, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn cancellation_requires_both_proofs_and_is_one_use(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.flow.start().await.unwrap();
    let wrong = Secret::generate().unwrap();
    let wrong_browser = SamlBrowserProof::parse(wrong.expose().to_owned()).unwrap();
    assert!(matches!(
        f.flow
            .cancel(start.request_id(), start.relay_state(), &wrong_browser)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow
            .cancel(start.request_id(), &wrong, start.browser_proof())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 1);
    f.flow
        .cancel(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    assert_eq!(f.pending().await, 0);
    assert!(matches!(
        f.flow
            .cancel(
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_cancellations_have_one_winner_without_signature_work(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.flow.start().await.unwrap();
    let (a, b) = tokio::join!(
        f.flow.cancel(
            start.request_id(),
            start.relay_state(),
            start.browser_proof()
        ),
        f.flow.cancel(
            start.request_id(),
            start.relay_state(),
            start.browser_proof()
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(a.err().or(b.err()), Some(Error::Unauthorized)));
    assert_eq!(f.pending().await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn identical_ids_and_proofs_in_other_realm_remain_isolated(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.flow.start().await.unwrap();
    let realm = Uuid::new_v4();
    f.store.ensure_realm(realm).await.unwrap();
    let other = f
        .store
        .configure_saml_registration(&registration(
            realm,
            f.registration.connection(),
            f.registration.client(),
        ))
        .await
        .unwrap();
    let admission = || SamlRequestAdmission {
        request_id: start.request_id(),
        relay: start.relay_state().verifier(),
        browser: Secret::parse(start.browser_proof().expose().to_owned())
            .unwrap()
            .verifier(),
    };
    f.store
        .save_saml_request(&other, admission())
        .await
        .unwrap();
    f.store
        .cancel_saml_request(&other, admission())
        .await
        .unwrap();
    assert_eq!(f.pending().await, 1);
    f.flow
        .cancel(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn storage_failure_is_unavailable_and_cancellation_rolls_back(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.flow.start().await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_saml_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned storage fault'; END $$; CREATE TRIGGER reject_saml_delete BEFORE DELETE ON auth_saml_requests FOR EACH ROW EXECUTE FUNCTION reject_saml_delete()")
        .execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.flow
            .cancel(
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.pending().await, 1);
    sqlx::query("DROP TRIGGER reject_saml_delete ON auth_saml_requests")
        .execute(&f.pool)
        .await
        .unwrap();
    f.flow
        .cancel(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn another_client_cannot_cancel_an_operation_in_the_same_realm_and_connection(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let first = f.flow.start().await.unwrap();
    let other = f
        .store
        .configure_saml_registration(&registration(
            f.registration.realm(),
            f.registration.connection(),
            Uuid::new_v4(),
        ))
        .await
        .unwrap();
    let other_flow = SamlTransactions::new(other, f.store.clone());
    let second = other_flow.start().await.unwrap();
    assert!(matches!(
        other_flow
            .cancel(
                first.request_id(),
                first.relay_state(),
                first.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow
            .cancel(
                second.request_id(),
                second.relay_state(),
                second.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 1);
    f.flow
        .cancel(
            first.request_id(),
            first.relay_state(),
            first.browser_proof(),
        )
        .await
        .unwrap();
    other_flow
        .cancel(
            second.request_id(),
            second.relay_state(),
            second.browser_proof(),
        )
        .await
        .unwrap();
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_saml_requests")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(pending, 0);
}
