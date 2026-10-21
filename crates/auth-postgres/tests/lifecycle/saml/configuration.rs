use super::setup::Fixture;
use auth_core::{Error, SamlTransactions};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn reconfiguration_and_disable_cancel_pending_and_cannot_revive_old_snapshots(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.flow.start().await.unwrap();
    let updated = f
        .store
        .configure_saml_registration(&f.registration)
        .await
        .unwrap();
    assert_ne!(updated.revision(), f.registration.revision());
    assert_eq!(f.pending().await, 0);
    assert!(matches!(f.flow.start().await, Err(Error::Unauthorized)));
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
    let flow = SamlTransactions::new(updated.clone(), f.store.clone());
    flow.start().await.unwrap();
    f.store
        .disable_saml_registration(updated.realm(), updated.connection(), updated.client())
        .await
        .unwrap();
    assert_eq!(f.pending().await, 0);
    assert!(matches!(flow.start().await, Err(Error::Unauthorized)));
    let latest = f.store.configure_saml_registration(&updated).await.unwrap();
    let latest_flow = SamlTransactions::new(latest.clone(), f.store.clone());
    assert!(matches!(
        latest_flow.start().await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.store.enable_saml_registration(&updated).await,
        Err(Error::Unauthorized)
    ));
    f.store.enable_saml_registration(&latest).await.unwrap();
    latest_flow.start().await.unwrap();
    assert_eq!(f.pending().await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn administrative_failure_rolls_back_registration_and_pending_cancellation(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.flow.start().await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_saml_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned storage fault'; END $$; CREATE TRIGGER reject_saml_delete BEFORE DELETE ON auth_saml_requests FOR EACH ROW EXECUTE FUNCTION reject_saml_delete()")
        .execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.store.configure_saml_registration(&f.registration).await,
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
