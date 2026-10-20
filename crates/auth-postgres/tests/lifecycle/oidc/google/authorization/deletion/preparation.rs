use super::super::super::{session_age::setup::selected, setup::Fixture};
use super::super::setup::response;
use super::setup::*;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::{Arc, atomic::Ordering};

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_deletion_failed_preparation_cleans_only_its_operation(pool: PgPool) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let (user, session) = account(&f).await;
    let service = service(&f);
    let browser = Secret::generate().unwrap();
    let bound = intent(&browser, &user, &session);
    let before = f.provider.document_gets.load(Ordering::SeqCst);
    f.provider
        .documents_unavailable
        .store(true, Ordering::SeqCst);
    assert!(matches!(
        service.begin(&bound).await,
        Err(Error::Unavailable)
    ));
    assert!(
        f.provider.document_gets.load(Ordering::SeqCst) > before,
        "actual provider document failure observed"
    );
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.store
            .authenticate(f.realm(), session.verifier())
            .await
            .unwrap(),
        user
    );
    f.provider
        .documents_unavailable
        .store(false, Ordering::SeqCst);
    let a = initiated(
        &f,
        &service,
        &user,
        &session,
        json!({"auth_time":now(&f).await}),
    )
    .await;
    // Both public sign-in constructors retain their original purpose restriction.
    let ordinary = GoogleAuthorization::new(Arc::new(f.flow()), f.google.clone()).unwrap();
    let selected =
        GoogleAuthorization::new_session_age(Arc::new(f.flow()), Arc::new(selected(&f))).unwrap();
    for sign_in in [ordinary, selected] {
        assert!(matches!(
            sign_in.begin(&bound).await,
            Err(Error::Unauthorized)
        ));
        let original = intent(&a.browser, &user, &session);
        assert!(matches!(
            sign_in
                .finish(
                    &original,
                    &a.start.state,
                    a.proof(),
                    f.policy.configuration().redirect(),
                    response(&a, None)
                )
                .await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            sign_in
                .cancel(&original, &a.start.state, &a.start.proof)
                .await,
            Err(Error::Unauthorized)
        ));
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
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
