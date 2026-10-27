use super::{
    linking::signed_in_owner,
    setup::{Fixture, wait_for_sql},
};
use auth_core::{Error, OAuthPurpose, OAuthTransactionRepository};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};

#[sqlx::test(migrations = "./migrations")]
async fn disabling_connection_first_rejects_waiting_callback(pool: PgPool) {
    let f = Arc::new(Fixture::new(pool.clone()).await);
    let start = f.start().await;
    let request = f.request(&start, OAuthPurpose::SignIn);
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(2202)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION oauth_disable_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(2202); RETURN NEW; END $$; CREATE TRIGGER oauth_disable_gate AFTER UPDATE ON auth_oauth_connections FOR EACH ROW EXECUTE FUNCTION oauth_disable_gate();")
        .execute(&pool).await.unwrap();
    let disabling = {
        let f = f.clone();
        tokio::spawn(async move {
            f.store
                .disable_oauth_connection(
                    f.connection.realm(),
                    f.connection.connection(),
                    f.connection.client(),
                )
                .await
        })
    };
    wait_for_sql(&pool, "UPDATE auth_oauth_connections SET enabled=false%").await;
    let consuming = {
        let f = f.clone();
        tokio::spawn(async move { f.store.consume_oauth(&request).await })
    };
    wait_for_sql(
        &pool,
        "%SELECT enabled FROM auth_oauth_connections%FOR SHARE%",
    )
    .await;
    gate.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), disabling)
        .await
        .expect("test infrastructure: disable completion")
        .unwrap()
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), consuming)
        .await
        .expect("test infrastructure: callback completion")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.pending().await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn callback_claim_first_serializes_disable_without_holding_locks_for_network(pool: PgPool) {
    let f = Arc::new(Fixture::new(pool.clone()).await);
    let (user, session) = signed_in_owner(&f).await;
    let purpose = OAuthPurpose::Link {
        user,
        session: session.verifier(),
    };
    let start = f.flow.begin(&f.intent(purpose.clone())).await.unwrap();
    let request = f.request(&start, purpose);
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .execute(&mut *gate)
        .await
        .unwrap();
    let consuming = {
        let f = f.clone();
        tokio::spawn(async move { f.store.consume_oauth(&request).await })
    };
    wait_for_sql(
        &pool,
        // Shared source-aware authorization also checks the original email
        // snapshot. Observe that actual owner lock without omitting the predicate.
        "%SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2%FOR UPDATE%",
    )
    .await;
    let disabling = {
        let f = f.clone();
        tokio::spawn(async move {
            f.store
                .disable_oauth_connection(
                    f.connection.realm(),
                    f.connection.connection(),
                    f.connection.client(),
                )
                .await
        })
    };
    wait_for_sql(&pool, "UPDATE auth_oauth_connections SET enabled=false%").await;
    gate.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), consuming)
        .await
        .expect("test infrastructure: callback completion")
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), disabling)
        .await
        .expect("test infrastructure: disable completion")
        .unwrap()
        .unwrap();
    assert_eq!(f.pending().await, 0);
    assert!(matches!(
        f.flow.begin(&f.intent(OAuthPurpose::SignIn)).await,
        Err(Error::Unauthorized)
    ));
    // This earlier state claim cannot authorize an identity after disable. That
    // final provider-proof/configuration revalidation belongs to AUTH-23/25.
    let enabled: bool = sqlx::query_scalar("SELECT enabled FROM auth_oauth_connections")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!enabled);
}
