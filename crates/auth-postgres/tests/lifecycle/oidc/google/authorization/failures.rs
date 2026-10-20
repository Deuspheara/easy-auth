use super::super::setup::Fixture;
use super::setup::*;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_failed_start_cleans_its_pending_operation_without_hiding_provider_failure(
    pool: PgPool,
) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let service = service(&f);
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "owned-google-postgres",
        purpose: OAuthPurpose::SignIn,
    };
    f.provider
        .documents_unavailable
        .store(true, Ordering::SeqCst);
    assert!(matches!(
        service.begin(&intent).await,
        Err(Error::Unavailable)
    ));
    assert!(
        f.provider.document_gets.load(Ordering::SeqCst) > 0,
        "actual injected document failure observed"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    f.provider
        .documents_unavailable
        .store(false, Ordering::SeqCst);
    let a = initiated(&f, &service, json!({})).await;
    commit(&f, finish(&f, &service, &a, None).await.unwrap()).await;
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_cancellation_storage_failure_is_not_reported_as_provider_denial(
    pool: PgPool,
) {
    let f = Fixture::new(pool, true, OidcJitPolicy::Allow).await;
    let service = service(&f);
    let a = initiated(&f, &service, json!({})).await;
    sqlx::raw_sql("CREATE FUNCTION owned_google_cancel_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned cancellation fault'; END $$; CREATE TRIGGER owned_google_cancel_fault BEFORE DELETE ON auth_oauth_transactions FOR EACH ROW EXECUTE FUNCTION owned_google_cancel_fault()")
        .execute(&f.pool).await.expect("test infrastructure: install owned cancellation failure");
    assert!(matches!(
        finish(&f, &service, &a, Some("access_denied")).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    sqlx::raw_sql("DROP TRIGGER owned_google_cancel_fault ON auth_oauth_transactions; DROP FUNCTION owned_google_cancel_fault()")
        .execute(&f.pool).await.expect("test infrastructure: remove owned cancellation failure");
    assert!(matches!(
        finish(&f, &service, &a, Some("access_denied"))
            .await
            .unwrap(),
        GoogleAuthorizationCompletion::Denied
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    let a = initiated(&f, &service, json!({})).await;
    commit(&f, finish(&f, &service, &a, None).await.unwrap()).await;
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_signed_rejection_and_token_infrastructure_failure_remain_distinct_and_one_use(
    pool: PgPool,
) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let service = service(&f);
    let a = initiated(
        &f,
        &service,
        json!({"nonce": Secret::generate().unwrap().expose()}),
    )
    .await;
    assert!(matches!(
        finish(&f, &service, &a, None).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.provider.signed.load(Ordering::SeqCst),
        1,
        "actual signed negative control"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    let a = initiated(&f, &service, json!({})).await;
    f.provider.unavailable.store(true, Ordering::SeqCst);
    assert!(matches!(
        finish(&f, &service, &a, None).await,
        Err(Error::Unavailable)
    ));
    f.provider.unavailable.store(false, Ordering::SeqCst);
    assert!(matches!(
        finish(&f, &service, &a, None).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    let a = initiated(&f, &service, json!({})).await;
    commit(&f, finish(&f, &service, &a, None).await.unwrap()).await;
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 3);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
}
