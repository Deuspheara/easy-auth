use super::setup::Fixture;
use auth_core::Error;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn preparation_and_cancellation_have_one_database_winner_without_signature_work(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let start = f.requests.start(&f.current).await.unwrap();
    let (prepared, cancelled) = tokio::join!(
        f.requests.prepare_response(
            &f.current,
            start.request_id(),
            start.relay_state(),
            start.browser_proof()
        ),
        f.requests.cancel(
            &f.current,
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
    assert_eq!(super::super::setup::facts(&f.source).await, (1, 1, 1, 2, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_consumption_rolls_back_and_reports_unavailable_before_valid_control(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.requests.start(&f.current).await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_deletion_take() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned fixture storage failure'; END $$; CREATE TRIGGER reject_deletion_take BEFORE DELETE ON auth_saml_requests FOR EACH ROW EXECUTE FUNCTION reject_deletion_take();")
        .execute(&f.source.pool).await.unwrap();
    assert!(matches!(
        f.requests
            .prepare_response(
                &f.current,
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.pending().await, 1);
    sqlx::raw_sql("DROP TRIGGER reject_deletion_take ON auth_saml_requests; DROP FUNCTION reject_deletion_take();")
        .execute(&f.source.pool).await.unwrap();
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
    assert_eq!(prepared.binding().user, f.user.id);
    assert_eq!(f.pending().await, 0);
    assert_eq!(super::super::setup::facts(&f.source).await, (1, 1, 1, 2, 1));
}
