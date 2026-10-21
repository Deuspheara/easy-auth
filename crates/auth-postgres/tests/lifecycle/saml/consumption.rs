use super::setup::{Fixture, registration};
use auth_core::{Error, SamlBrowserProof, SamlTransactions, Secret};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn preparation_consumes_both_bound_proofs_and_preserves_original_database_deadline(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let start = f.flow.start().await.unwrap();
    let cap: i64 = sqlx::query_scalar("SELECT (extract(epoch FROM expires_at)*1000000)::bigint FROM auth_saml_requests WHERE realm_id=$1 AND request_id=$2")
        .bind(f.registration.realm()).bind(start.request_id()).fetch_one(&f.pool).await.unwrap();
    let wrong = Secret::generate().unwrap();
    let wrong_browser = SamlBrowserProof::parse(wrong.expose().to_owned()).unwrap();
    for (relay, browser) in [
        (start.relay_state(), &wrong_browser),
        (&wrong, start.browser_proof()),
    ] {
        assert!(matches!(
            f.flow
                .prepare_response(start.request_id(), relay, browser)
                .await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(f.pending().await, 1);
    }
    let prepared = f
        .flow
        .prepare_response(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    assert_eq!(prepared.request_id(), start.request_id());
    assert_eq!(prepared.registration(), &f.registration);
    assert_eq!(prepared.expires_at_us(), cap);
    assert_eq!(prepared.expires_at_us() / 1000, start.expires_at_ms());
    assert!(prepared.observed_at_us() > 0 && prepared.observed_at_us() < cap);
    assert_eq!(
        format!("{prepared:?}"),
        "SamlPreparedResponse([REDACTED; not authenticated])"
    );
    assert_eq!(f.pending().await, 0);
    assert!(matches!(
        f.flow
            .prepare_response(
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
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
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions)",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(counts, (0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn preparation_and_cancellation_share_one_database_winner_without_signature_work(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let start = f.flow.start().await.unwrap();
    let (prepared, cancelled) = tokio::join!(
        f.flow.prepare_response(
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
    assert_eq!(
        usize::from(prepared.is_ok()) + usize::from(cancelled.is_ok()),
        1
    );
    assert!(matches!(
        prepared.err().or(cancelled.err()),
        Some(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn preparation_requires_current_namespace_revision_and_unexpired_state(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let other = Fixture::new(pool).await;
    let start = f.flow.start().await.unwrap();
    let other_registration = other
        .store
        .configure_saml_registration(&registration(
            other.registration.realm(),
            f.registration.connection(),
            f.registration.client(),
        ))
        .await
        .unwrap();
    let other_flow = SamlTransactions::new(other_registration, other.store.clone());
    assert!(matches!(
        other_flow
            .prepare_response(
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 1);
    for id in ["", "wrong-id-shape", "_invalid\n"] {
        assert!(matches!(
            f.flow
                .prepare_response(id, start.relay_state(), start.browser_proof())
                .await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(f.pending().await, 1);
    }
    sqlx::query("UPDATE auth_saml_requests SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 second' WHERE realm_id=$1")
        .bind(f.registration.realm()).execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.flow
            .prepare_response(
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let current = f
        .store
        .configure_saml_registration(&f.registration)
        .await
        .unwrap();
    assert!(matches!(
        f.flow
            .prepare_response(
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let flow = SamlTransactions::new(current, f.store.clone());
    let healthy = flow.start().await.unwrap();
    assert!(
        flow.prepare_response(
            healthy.request_id(),
            healthy.relay_state(),
            healthy.browser_proof()
        )
        .await
        .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_consumption_is_unavailable_and_rolls_back_pending_request(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.flow.start().await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_saml_consumption() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'storage fixture'; END $$; CREATE TRIGGER reject_saml_consumption BEFORE DELETE ON auth_saml_requests FOR EACH ROW EXECUTE FUNCTION reject_saml_consumption()")
        .execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.flow
            .prepare_response(
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.pending().await, 1);
    sqlx::query("DROP TRIGGER reject_saml_consumption ON auth_saml_requests")
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        f.flow
            .prepare_response(
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await
            .is_ok()
    );
}
