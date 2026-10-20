use super::super::super::setup::Fixture;
use super::setup::*;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_deletion_callback_race_exchanges_once_before_separate_deletion(
    pool: PgPool,
) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let service = service(&f);
    let (user, session) = account(&f).await;
    let a = initiated(
        &f,
        &service,
        &user,
        &session,
        json!({"auth_time":now(&f).await}),
    )
    .await;
    let (left, right) = tokio::join!(
        finish(&f, &service, &a, &user, &session, None),
        finish(&f, &service, &a, &user, &session, None)
    );
    let completed = match (left, right) {
        (Ok(completed), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(completed)) => {
            completed
        }
        _ => panic!("exactly one bound deletion callback must verify"),
    };
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 2);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
    assert_eq!(
        f.facts().await,
        (1, 1, 1, 1, 0),
        "callback completion alone cannot delete"
    );
    remove(&f, completed).await.unwrap();
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
    assert!(matches!(
        f.store.authenticate(f.realm(), session.verifier()).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_deletion_final_audit_failure_rolls_back_account_but_not_callback_consumption(
    pool: PgPool,
) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let service = service(&f);
    let (user, session) = account(&f).await;
    let a = initiated(
        &f,
        &service,
        &user,
        &session,
        json!({"auth_time":now(&f).await}),
    )
    .await;
    let completed = finish(&f, &service, &a, &user, &session, None)
        .await
        .unwrap();
    let before = super::super::super::session_age::setup::snapshot(&f).await;
    sqlx::raw_sql("CREATE FUNCTION owned_google_managed_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned managed deletion audit fault'; END $$; CREATE TRIGGER owned_google_managed_audit_fault BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION owned_google_managed_audit_fault()")
        .execute(&f.pool).await.expect("test infrastructure: install managed deletion audit fault");
    assert!(matches!(
        remove(&f, completed).await,
        Err(Error::Unavailable)
    ));
    assert!(
        super::super::super::session_age::setup::snapshot(&f).await == before,
        "private full account state must match after rollback"
    );
    assert!(matches!(
        finish(&f, &service, &a, &user, &session, None).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.store
            .authenticate(f.realm(), session.verifier())
            .await
            .unwrap(),
        user
    );
    sqlx::raw_sql("DROP TRIGGER owned_google_managed_audit_fault ON auth_audit; DROP FUNCTION owned_google_managed_audit_fault()")
        .execute(&f.pool).await.expect("test infrastructure: remove managed deletion audit fault");
    let a = initiated(
        &f,
        &service,
        &user,
        &session,
        json!({"auth_time":now(&f).await}),
    )
    .await;
    remove(
        &f,
        finish(&f, &service, &a, &user, &session, None)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
}
