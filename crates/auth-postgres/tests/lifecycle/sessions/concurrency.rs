use super::session;
use crate::support::{realm, signed_in};
use auth_core::Repository;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_revoke_all_has_one_winner_and_one_audit(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let first = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, first.verifier()).await.unwrap();
    let (second, _) = session(&pool, realm, user.id).await;
    let (a, b) = tokio::join!(
        store.revoke_all_sessions(realm, first.verifier()),
        store.revoke_all_sessions(realm, second.verifier())
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert!(store.authenticate(realm, first.verifier()).await.is_err());
    assert!(store.authenticate(realm, second.verifier()).await.is_err());
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='all_sessions_revoked'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn login_waits_for_revoke_all_commit_then_can_issue_a_new_session(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    // Repository fixture: password verification happens in core; this test exercises transaction ordering.
    sqlx::query("INSERT INTO auth_password_credentials(realm_id,user_id,password_hash) VALUES ($1,$2,'verified-test-hash')")
        .bind(realm).bind(user.id).execute(&pool).await.unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(150015)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION gate_revocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN PERFORM pg_advisory_xact_lock(150015); END IF; RETURN NEW; END $$; CREATE TRIGGER gate_revocation BEFORE UPDATE ON auth_sessions FOR EACH ROW EXECUTE FUNCTION gate_revocation();")
        .execute(&pool).await.unwrap();
    let revoke_store = store.clone();
    let verifier = current.verifier();
    let revoke =
        tokio::spawn(async move { revoke_store.revoke_all_sessions(realm, verifier).await });
    // A waiting trigger proves revoke-all already holds the user/session locks; no timing assumption.
    wait_for_advisory(&pool).await;
    let login_store = store.clone();
    let new = auth_core::Secret::generate().unwrap();
    let new_verifier = new.verifier();
    let login = tokio::spawn(async move {
        login_store
            .password_login(
                realm,
                "alice@example.com",
                "verified-test-hash",
                new_verifier,
            )
            .await
    });
    wait_for_user_lock(&pool).await;
    gate.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), revoke)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), login)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(store.authenticate(realm, current.verifier()).await.is_err());
    assert!(store.authenticate(realm, new.verifier()).await.is_ok());
}

async fn wait_for_advisory(pool: &PgPool) {
    wait_for(pool, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=150015 AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT granted)").await;
}
async fn wait_for_user_lock(pool: &PgPool) {
    wait_for(pool, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id FROM auth_users%FOR UPDATE%')").await;
}
async fn wait_for(pool: &PgPool, query: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(query).fetch_one(pool).await.unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn login_committed_before_revoke_all_is_included_in_revocation(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    sqlx::query("INSERT INTO auth_password_credentials(realm_id,user_id,password_hash) VALUES ($1,$2,'verified-test-hash')")
        .bind(realm).bind(user.id).execute(&pool).await.unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(150015)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION gate_login() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='password_authenticated' THEN PERFORM pg_advisory_xact_lock(150015); END IF; RETURN NEW; END $$; CREATE TRIGGER gate_login BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION gate_login();")
        .execute(&pool).await.unwrap();
    let new = auth_core::Secret::generate().unwrap();
    let new_verifier = new.verifier();
    let login_store = store.clone();
    let login = tokio::spawn(async move {
        login_store
            .password_login(
                realm,
                "alice@example.com",
                "verified-test-hash",
                new_verifier,
            )
            .await
    });
    wait_for_advisory(&pool).await;
    let revoke_store = store.clone();
    let verifier = current.verifier();
    let revoke =
        tokio::spawn(async move { revoke_store.revoke_all_sessions(realm, verifier).await });
    wait_for_user_lock(&pool).await;
    gate.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), login)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), revoke)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(store.authenticate(realm, current.verifier()).await.is_err());
    assert!(store.authenticate(realm, new.verifier()).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn freshness_is_revalidated_after_waiting_for_the_user_lock(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let (target, id) = session(&pool, realm, user.id).await;
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(realm)
        .bind(user.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let revoke_store = store.clone();
    let verifier = current.verifier();
    let revoke =
        tokio::spawn(async move { revoke_store.revoke_session(realm, verifier, id).await });
    wait_for_user_lock(&pool).await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1")
        .bind(current.verifier().as_slice()).execute(&pool).await.unwrap();
    blocker.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), revoke)
            .await
            .unwrap()
            .unwrap(),
        Err(auth_core::Error::Unauthorized)
    ));
    assert!(store.authenticate(realm, target.verifier()).await.is_ok());
}
