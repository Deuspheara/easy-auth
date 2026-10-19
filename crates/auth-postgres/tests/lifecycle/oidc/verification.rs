use super::setup::Fixture;
use crate::support::signed_in;
use auth_core::{Error, OAuthPurpose, OidcExchangeRepository, Repository};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn checked_exchange_has_current_db_time_but_creates_no_authentication_records(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let exchange = f.exchange(OAuthPurpose::SignIn).await;
    let now = f.store.check_oidc_exchange(&exchange).await.unwrap();
    assert!(now > 0 && now < exchange.expires_us());
    let facts:(i64,i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_oauth_transactions),(SELECT count(*) FROM auth_audit)").fetch_one(&f.pool).await.unwrap();
    assert_eq!(facts, (0, 0, 0, 0));
    let current = f
        .store
        .configure_oauth_connection(&f.connection)
        .await
        .unwrap();
    assert_ne!(current.revision(), exchange.configuration().revision());
    assert!(matches!(
        f.store.check_oidc_exchange(&exchange).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn identical_configuration_in_another_realm_cannot_authorize_the_exchange(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let exchange = f.exchange(OAuthPurpose::SignIn).await;
    f.store.check_oidc_exchange(&exchange).await.unwrap();
    let realm = Uuid::new_v4();
    f.store.ensure_realm(realm).await.unwrap();
    sqlx::query("UPDATE auth_oauth_connections SET realm_id=$1 WHERE realm_id=$2")
        .bind(realm)
        .bind(f.connection.realm())
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.store.check_oidc_exchange(&exchange).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn broken_exchange_registry_is_unavailable_not_authorization_rejection(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let exchange = f.exchange(OAuthPurpose::SignIn).await;
    f.store.check_oidc_exchange(&exchange).await.unwrap();
    sqlx::query("DROP TABLE auth_oauth_connections CASCADE")
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.store.check_oidc_exchange(&exchange).await,
        Err(Error::Unavailable)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn checked_linking_exchange_rechecks_original_session_revocation(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let session = signed_in(&f.store, f.connection.realm(), "oidc-owner@example.test").await;
    let owner = f
        .store
        .authenticate(f.connection.realm(), session.verifier())
        .await
        .unwrap();
    let exchange = f
        .exchange(OAuthPurpose::Link {
            user: owner.id,
            session: session.verifier(),
        })
        .await;
    f.store.check_oidc_exchange(&exchange).await.unwrap();
    f.store
        .revoke(f.connection.realm(), session.verifier())
        .await
        .unwrap();
    assert!(matches!(
        f.store.check_oidc_exchange(&exchange).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn later_freshness_cannot_extend_the_linking_exchanges_original_cap(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let session = signed_in(
        &f.store,
        f.connection.realm(),
        "oidc-original-cap@example.test",
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
        .expect("test infrastructure: original cap initially live");
    // Privileged state fixture isolates the retained cap from current freshness.
    // This is no authentication endpoint, provenance bypass or real reauth claim.
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp() WHERE realm_id=$1 AND user_id=$2").bind(f.connection.realm()).bind(owner.id).execute(&f.pool).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    f.store
        .authenticate(f.connection.realm(), session.verifier())
        .await
        .expect("test infrastructure: original session remains active");
    assert!(
        matches!(
            f.store.check_oidc_exchange(&exchange).await,
            Err(Error::Unauthorized)
        ),
        "a later timestamp must not restart the consumed linking proof's deadline"
    );
}
