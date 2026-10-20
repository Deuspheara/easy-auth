use super::setup::{Fixture, connection};
use auth_core::{Error, OAuthPurpose, OAuthTransactionRepository, OAuthTransactions, Secret};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn browser_capacity_spans_connections_and_expired_rows_release_capacity(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let first = f.start().await;
    for _ in 0..2 {
        let connection = connection(f.connection.realm(), Uuid::new_v4(), Uuid::new_v4());
        let connection = f
            .store
            .configure_oauth_connection(&connection)
            .await
            .unwrap();
        OAuthTransactions::new(connection, f.store.clone())
            .begin(&f.intent(OAuthPurpose::SignIn))
            .await
            .unwrap();
    }
    assert!(matches!(
        f.flow.begin(&f.intent(OAuthPurpose::SignIn)).await,
        Err(Error::RateLimited)
    ));
    assert_eq!(f.pending().await, 3);
    sqlx::query("UPDATE auth_oauth_transactions SET expires_at=created_at+interval '1 microsecond' WHERE state_hash=$1")
        .bind(first.state.verifier().as_slice()).execute(&f.pool).await.unwrap();
    f.start().await;
    assert_eq!(f.pending().await, 3);
}

#[sqlx::test(migrations = "./migrations")]
async fn realm_capacity_and_source_admission_are_independent_of_browser_identity(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let first = f.start().await;
    // Capacity-only fixtures: these hashes are not evidence of usable proof.
    sqlx::query("INSERT INTO auth_oauth_transactions(realm_id,connection_id,client_id,revision,state_hash,browser_hash,nonce_hash,pkce_hash,purpose,created_at,expires_at,redirect_uri) SELECT realm_id,connection_id,client_id,revision,sha256(int4send(n)),sha256(int4send(n)),nonce_hash,pkce_hash,purpose,created_at,expires_at,redirect_uri FROM auth_oauth_transactions CROSS JOIN generate_series(1,255) n")
        .execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.flow.begin(&f.intent(OAuthPurpose::SignIn)).await,
        Err(Error::RateLimited)
    ));
    assert_eq!(f.pending().await, 256);
    sqlx::query("DELETE FROM auth_oauth_transactions WHERE state_hash<>$1")
        .bind(first.state.verifier().as_slice())
        .execute(&f.pool)
        .await
        .unwrap();
    let mut request = f.request(&first, OAuthPurpose::SignIn);
    request.state = Secret::generate().unwrap().verifier();
    sqlx::query("INSERT INTO auth_oauth_admission(realm_id,dimension,key_hash,window_id,attempts) SELECT $1,'start_source',sha256($2),n,40 FROM generate_series(floor(extract(epoch FROM clock_timestamp())/600)::bigint,floor(extract(epoch FROM clock_timestamp())/600)::bigint+1) n")
        .bind(f.connection.realm()).bind(request.source.as_slice()).execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.store.save_oauth(&request).await,
        Err(Error::RateLimited)
    ));
    assert_eq!(f.pending().await, 1);
}
