use super::setup::Fixture;
use auth_core::{
    Error, OAuthCallback, OAuthIntent, OAuthPurpose, OAuthTransactions, OidcExchangeRepository,
    Secret,
};
use sqlx::PgPool;
use std::time::Duration;

async fn wait_for_lock(pool: &PgPool, pattern: &str) {
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: one-connection OIDC observer");
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)").bind(pattern).fetch_one(&observer).await.expect("test infrastructure: observe OIDC context lock");
            if waiting {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: context did not reach its configuration lock");
    observer.close().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn context_wait_rechecks_original_expiry_after_an_unchanged_configuration_row(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "oidc-owned-expiry",
        purpose: OAuthPurpose::SignIn,
    };
    let flow = OAuthTransactions::new(f.connection.clone(), f.store.clone());
    let start = flow.begin(&intent).await.unwrap();
    sqlx::query("UPDATE auth_oauth_transactions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE realm_id=$1").bind(f.connection.realm()).execute(&f.pool).await.unwrap();
    let exchange = flow
        .consume(
            &intent,
            &start.state,
            start.proof,
            OAuthCallback {
                redirect: f.connection.redirect(),
                issuer: Some(f.connection.issuer()),
            },
        )
        .await
        .unwrap();
    f.store.check_oidc_exchange(&exchange).await.unwrap();
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_oauth_connections WHERE realm_id=$1 FOR UPDATE")
        .bind(f.connection.realm())
        .fetch_one(&mut *gate)
        .await
        .unwrap();
    let action = {
        let store = f.store.clone();
        tokio::spawn(async move { store.check_oidc_exchange(&exchange).await })
    };
    wait_for_lock(&f.pool, "%FROM auth_oauth_connections WHERE%").await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("test infrastructure: released context finishes")
        .unwrap();
    assert!(
        matches!(result, Err(Error::Unauthorized)),
        "an infrastructure error cannot prove expiry rejection"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn linking_context_rechecks_original_freshness_after_an_unchanged_owner_wait(pool: PgPool) {
    use crate::support::signed_in;
    use auth_core::Repository;
    let f = Fixture::new(pool).await;
    let session = signed_in(
        &f.store,
        f.connection.realm(),
        "oidc-wait-owner@example.test",
    )
    .await;
    let owner = f
        .store
        .authenticate(f.connection.realm(), session.verifier())
        .await
        .unwrap();
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '5 minutes'+interval '2 seconds' WHERE realm_id=$1 AND user_id=$2").bind(f.connection.realm()).bind(owner.id).execute(&f.pool).await.unwrap();
    let exchange = f
        .exchange(OAuthPurpose::Link {
            user: owner.id,
            session: session.verifier(),
        })
        .await;
    f.store
        .check_oidc_exchange(&exchange)
        .await
        .expect("test infrastructure: linking context initially live");
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(f.connection.realm())
        .bind(owner.id)
        .fetch_one(&mut *gate)
        .await
        .unwrap();
    let action = {
        let store = f.store.clone();
        tokio::spawn(async move { store.check_oidc_exchange(&exchange).await })
    };
    wait_for_lock(
        &f.pool,
        // The shared owner lock retains an additional email-snapshot predicate;
        // the wait, original cap and rejection assertions remain authoritative.
        "%SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2%FOR UPDATE%",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("test infrastructure: released linking context finishes")
        .unwrap();
    assert!(
        matches!(result, Err(Error::Unauthorized)),
        "infrastructure failure is not proof of freshness enforcement"
    );
}
