use super::super::super::setup::Fixture;
use super::setup::*;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_deletion_storage_failure_cannot_masquerade_as_provider_denial(
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
    sqlx::raw_sql("CREATE FUNCTION owned_google_deletion_cancel_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned deletion cancellation fault'; END $$; CREATE TRIGGER owned_google_deletion_cancel_fault BEFORE DELETE ON auth_oauth_transactions FOR EACH ROW EXECUTE FUNCTION owned_google_deletion_cancel_fault()")
        .execute(&f.pool).await.expect("test infrastructure: install actual deletion cancellation fault");
    assert!(matches!(
        finish(&f, &service, &a, &user, &session, Some("access_denied")).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.facts().await, (1, 1, 1, 1, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    sqlx::raw_sql("DROP TRIGGER owned_google_deletion_cancel_fault ON auth_oauth_transactions; DROP FUNCTION owned_google_deletion_cancel_fault()")
        .execute(&f.pool).await.expect("test infrastructure: remove actual deletion cancellation fault");
    assert!(matches!(
        finish(&f, &service, &a, &user, &session, Some("access_denied"))
            .await
            .unwrap(),
        GoogleAuthorizationCompletion::Denied
    ));
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert_eq!(
        f.store
            .authenticate(f.realm(), session.verifier())
            .await
            .unwrap(),
        user
    );
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

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_deletion_signed_claim_rejection_and_infrastructure_failure_are_distinct(
    pool: PgPool,
) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let service = service(&f);
    let (user, session) = account(&f).await;
    for (attributes, unavailable) in [
        (json!({}), true),
        (json!({"auth_time":null}), false),
        (
            json!({"auth_time":now(&f).await,"nonce":Secret::generate().unwrap().expose()}),
            false,
        ),
    ] {
        let before = f.provider.signed.load(Ordering::SeqCst);
        let a = initiated(&f, &service, &user, &session, attributes).await;
        assert!(matches!(
            (
                unavailable,
                finish(&f, &service, &a, &user, &session, None).await
            ),
            (true, Err(Error::Unavailable)) | (false, Err(Error::Unauthorized))
        ));
        assert_eq!(
            f.provider.signed.load(Ordering::SeqCst),
            before + 1,
            "actual signed response required"
        );
        assert!(matches!(
            finish(&f, &service, &a, &user, &session, None).await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    }
    let a = initiated(
        &f,
        &service,
        &user,
        &session,
        json!({"auth_time":now(&f).await}),
    )
    .await;
    let signed = f.provider.signed.load(Ordering::SeqCst);
    f.provider.unavailable.store(true, Ordering::SeqCst);
    assert!(matches!(
        finish(&f, &service, &a, &user, &session, None).await,
        Err(Error::Unavailable)
    ));
    f.provider.unavailable.store(false, Ordering::SeqCst);
    assert_eq!(
        f.provider.signed.load(Ordering::SeqCst),
        signed,
        "transport failure did not produce a signed denial"
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
    let old = now(&f).await - i64::try_from(MAX_OIDC_DELETION_AUTH_AGE_SECONDS).unwrap() - 1;
    let a = initiated(&f, &service, &user, &session, json!({"auth_time":old})).await;
    assert!(matches!(
        remove(
            &f,
            finish(&f, &service, &a, &user, &session, None)
                .await
                .unwrap()
        )
        .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
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
