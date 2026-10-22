use super::super::super::{setup::registration, signed_idp};
use super::setup::Fixture;
use auth_core::{Error, SamlDeletionRequests, SamlIdentityPolicy, SamlJitPolicy};
use sqlx::PgPool;
use std::sync::Arc;

#[sqlx::test(migrations = "./migrations")]
async fn identical_source_ids_in_another_realm_cannot_select_a_session_or_pending_operation(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone()).await;
    let (other, realm) = crate::support::realm(pool).await;
    let other = Arc::new(other);
    let reg = registration(
        realm,
        f.source.registration.connection(),
        f.source.registration.client(),
    );
    let policy = other
        .configure_saml_identity_policy(
            &SamlIdentityPolicy::new(reg).with_jit(SamlJitPolicy::Allow),
            &signed_idp::trust(),
        )
        .await
        .unwrap();
    let requests = SamlDeletionRequests::new(policy.registration().clone(), other.clone());
    let start = f.requests.start(&f.current).await.unwrap();
    assert!(matches!(
        requests.start(&f.current).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        requests
            .prepare_response(
                &f.current,
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        requests
            .cancel(
                &f.current,
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 1);
    assert_eq!(
        other
            .saml_identity_policy(policy.registration())
            .await
            .unwrap(),
        policy
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_saml_requests WHERE realm_id=$1")
            .bind(realm)
            .fetch_one(&f.source.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    f.requests
        .cancel(
            &f.current,
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    assert_eq!(f.pending().await, 0);
}
