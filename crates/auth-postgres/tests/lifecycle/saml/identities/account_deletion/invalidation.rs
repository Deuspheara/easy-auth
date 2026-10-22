use super::setup::{Fixture, counts};
use auth_core::{Error, Repository};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn logout_cancels_only_its_bound_deletion_requests_and_preserves_sign_in_and_other_sessions(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let same_owner = f.another_session("normal").await;
    let other_owner = f.another_session("other").await;
    let own = f.requests.start(&f.current).await.unwrap();
    let same = f.requests.start(&same_owner).await.unwrap();
    let other = f.requests.start(&other_owner).await.unwrap();
    let anonymous = f.source.flow.start().await.unwrap();
    assert_eq!(f.pending().await, 4);
    f.source
        .store
        .revoke(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
    assert_eq!(f.pending().await, 3);
    f.source
        .store
        .revoke(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
    assert_eq!(f.pending().await, 3);
    assert!(matches!(
        f.requests
            .prepare_response(
                &f.current,
                own.request_id(),
                own.relay_state(),
                own.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    f.requests
        .cancel(
            &same_owner,
            same.request_id(),
            same.relay_state(),
            same.browser_proof(),
        )
        .await
        .unwrap();
    f.requests
        .cancel(
            &other_owner,
            other.request_id(),
            other.relay_state(),
            other.browser_proof(),
        )
        .await
        .unwrap();
    f.source
        .flow
        .prepare_response(
            anonymous.request_id(),
            anonymous.relay_state(),
            anonymous.browser_proof(),
        )
        .await
        .unwrap();
    assert_eq!(f.pending().await, 0);
    f.source
        .store
        .authenticate(f.user.realm_id, same_owner.verifier())
        .await
        .unwrap();
    f.source
        .store
        .authenticate(f.user.realm_id, other_owner.verifier())
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn targeted_and_all_session_revocation_preserve_other_owner_realm_and_anonymous_sign_in(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone()).await;
    let foreign = Fixture::new(pool).await;
    let foreign_pending = foreign.requests.start(&foreign.current).await.unwrap();
    let target = f.another_session("normal").await;
    let other_owner = f.another_session("other").await;
    let own = f.requests.start(&f.current).await.unwrap();
    let target_pending = f.requests.start(&target).await.unwrap();
    let other = f.requests.start(&other_owner).await.unwrap();
    let anonymous = f.source.flow.start().await.unwrap();
    let page = f
        .source
        .store
        .list_sessions(f.user.realm_id, f.current.verifier(), None)
        .await
        .unwrap();
    let id = page.sessions.iter().find(|s| !s.current).unwrap().id;
    assert!(
        !f.source
            .store
            .revoke_session(f.user.realm_id, f.current.verifier(), id)
            .await
            .unwrap()
    );
    assert_eq!(f.pending().await, 3);
    assert!(matches!(
        f.requests
            .cancel(
                &target,
                target_pending.request_id(),
                target_pending.relay_state(),
                target_pending.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    f.source
        .store
        .revoke_all_sessions(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
    assert_eq!(f.pending().await, 2);
    assert_eq!(foreign.pending().await, 1);
    assert!(matches!(
        f.requests
            .cancel(
                &f.current,
                own.request_id(),
                own.relay_state(),
                own.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    f.requests
        .cancel(
            &other_owner,
            other.request_id(),
            other.relay_state(),
            other.browser_proof(),
        )
        .await
        .unwrap();
    f.source
        .flow
        .cancel(
            anonymous.request_id(),
            anonymous.relay_state(),
            anonymous.browser_proof(),
        )
        .await
        .unwrap();
    foreign
        .requests
        .cancel(
            &foreign.current,
            foreign_pending.request_id(),
            foreign_pending.relay_state(),
            foreign_pending.browser_proof(),
        )
        .await
        .unwrap();
    assert_eq!(f.pending().await, 0);
    f.source
        .store
        .authenticate(f.user.realm_id, other_owner.verifier())
        .await
        .unwrap();
    foreign
        .source
        .store
        .authenticate(foreign.user.realm_id, foreign.current.verifier())
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_logout_cleanup_rolls_back_session_audit_and_pending_state_before_valid_control(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let pending = f.requests.start(&f.current).await.unwrap();
    install_fault(&f.source.pool).await;
    assert!(matches!(
        f.source
            .store
            .revoke(f.user.realm_id, f.current.verifier())
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(counts(&f).await, (1, 1, 1, 2, 1, 1));
    f.source
        .store
        .authenticate(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
    remove_fault(&f.source.pool).await;
    f.source
        .store
        .revoke(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
    assert_eq!(counts(&f).await, (1, 1, 1, 2, 2, 0));
    assert!(matches!(
        f.requests
            .cancel(
                &f.current,
                pending.request_id(),
                pending.relay_state(),
                pending.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_targeted_or_all_cleanup_keeps_both_sessions_and_pending_operations(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let target = f.another_session("normal").await;
    let _own = f.requests.start(&f.current).await.unwrap();
    let _target_pending = f.requests.start(&target).await.unwrap();
    let page = f
        .source
        .store
        .list_sessions(f.user.realm_id, f.current.verifier(), None)
        .await
        .unwrap();
    let id = page.sessions.iter().find(|s| !s.current).unwrap().id;
    install_fault(&f.source.pool).await;
    assert!(matches!(
        f.source
            .store
            .revoke_session(f.user.realm_id, f.current.verifier(), id)
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(counts(&f).await, (1, 1, 2, 4, 2, 2));
    assert!(matches!(
        f.source
            .store
            .revoke_all_sessions(f.user.realm_id, f.current.verifier())
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(counts(&f).await, (1, 1, 2, 4, 2, 2));
    for current in [&f.current, &target] {
        f.source
            .store
            .authenticate(f.user.realm_id, current.verifier())
            .await
            .unwrap();
    }
    remove_fault(&f.source.pool).await;
    f.source
        .store
        .revoke_all_sessions(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
    assert_eq!(counts(&f).await, (1, 1, 2, 4, 3, 0));
}

async fn install_fault(pool: &PgPool) {
    sqlx::raw_sql("CREATE FUNCTION reject_saml_invalidation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned fixture storage failure'; END $$; CREATE TRIGGER reject_saml_invalidation BEFORE DELETE ON auth_saml_requests FOR EACH ROW WHEN (OLD.purpose='delete_account') EXECUTE FUNCTION reject_saml_invalidation();")
        .execute(pool).await.unwrap();
}
async fn remove_fault(pool: &PgPool) {
    sqlx::raw_sql("DROP TRIGGER reject_saml_invalidation ON auth_saml_requests; DROP FUNCTION reject_saml_invalidation();").execute(pool).await.unwrap();
}
