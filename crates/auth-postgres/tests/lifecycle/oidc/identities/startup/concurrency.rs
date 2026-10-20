use super::super::setup::wait_for_lock;
use super::setup::*;
use auth_core::*;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_initializers_converge_on_one_fresh_revision(pool: PgPool) {
    let (store, input) = empty(pool.clone()).await;
    let gate = initial_gate(&pool).await;
    let first = tokio::spawn({
        let store = store.clone();
        let input = input.clone();
        async move { store.load_or_initialize_oidc_identity_policy(&input).await }
    });
    let second = tokio::spawn({
        let store = store.clone();
        let input = input.clone();
        async move { store.load_or_initialize_oidc_identity_policy(&input).await }
    });
    observe_initial_inserts(&pool).await;
    gate.commit().await.unwrap();
    let first = first.await.unwrap().unwrap();
    let second = second.await.unwrap().unwrap();
    assert_eq!(first, second);
    assert_ne!(
        first.configuration().revision(),
        input.configuration().revision()
    );
    assert_eq!(counts(&pool).await, (1, 1, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn disable_committed_during_startup_wait_is_observed_without_reenable(pool: PgPool) {
    let (store, input) = empty(pool.clone()).await;
    let actual = store
        .load_or_initialize_oidc_identity_policy(&input)
        .await
        .unwrap();
    let c = actual.configuration();
    let mut disable = pool.begin().await.unwrap();
    sqlx::query("UPDATE auth_oauth_connections SET enabled=false,revision=$4 WHERE realm_id=$1 AND id=$2 AND client_id=$3")
        .bind(c.realm()).bind(c.connection()).bind(c.client()).bind(uuid::Uuid::new_v4()).execute(&mut *disable).await.unwrap();
    let task = tokio::spawn({
        let store = store.clone();
        let input = input.clone();
        async move { store.load_or_initialize_oidc_identity_policy(&input).await }
    });
    wait_for_lock(&pool, "SELECT revision FROM auth_oauth_connections%").await;
    disable.commit().await.unwrap();
    let before = snapshot(&pool).await;
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    assert!(before == snapshot(&pool).await);
}

#[sqlx::test(migrations = "./migrations")]
async fn admitted_startup_cannot_make_its_snapshot_current_after_waiting_disable(pool: PgPool) {
    let (store, input) = empty(pool.clone()).await;
    let actual = store
        .load_or_initialize_oidc_identity_policy(&input)
        .await
        .unwrap();
    let c = actual.configuration();
    let mut policy_gate = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM auth_oidc_identity_policies WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 FOR UPDATE")
        .bind(c.realm()).bind(c.connection()).bind(c.client()).execute(&mut *policy_gate).await.unwrap();
    let startup = tokio::spawn({
        let store = store.clone();
        let input = input.clone();
        async move { store.load_or_initialize_oidc_identity_policy(&input).await }
    });
    wait_for_lock(
        &pool,
        "SELECT allowed_issuers,display_claim,jit FROM auth_oidc_identity_policies%",
    )
    .await;
    let disable = tokio::spawn({
        let store = store.clone();
        let c = c.clone();
        async move {
            store
                .disable_oauth_connection(c.realm(), c.connection(), c.client())
                .await
        }
    });
    wait_for_lock(&pool, "UPDATE auth_oauth_connections SET enabled=false%").await;
    policy_gate.commit().await.unwrap();
    assert_eq!(startup.await.unwrap().unwrap(), actual);
    disable.await.unwrap().unwrap();
    assert!(matches!(
        store.check_oidc_connection(actual.configuration()).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        store.load_or_initialize_oidc_identity_policy(&input).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn competing_initial_definitions_have_one_winner_without_policy_overwrite(pool: PgPool) {
    let (store, input) = empty(pool.clone()).await;
    let other = input.clone().with_jit(OidcJitPolicy::Allow);
    let gate = initial_gate(&pool).await;
    let first = tokio::spawn({
        let store = store.clone();
        let input = input.clone();
        async move { store.load_or_initialize_oidc_identity_policy(&input).await }
    });
    let second = tokio::spawn({
        let store = store.clone();
        let input = other.clone();
        async move { store.load_or_initialize_oidc_identity_policy(&input).await }
    });
    observe_initial_inserts(&pool).await;
    gate.commit().await.unwrap();
    let (winner, definition) = match (first.await.unwrap(), second.await.unwrap()) {
        (Ok(winner), Err(Error::Unauthorized)) => (winner, input),
        (Err(Error::Unauthorized), Ok(winner)) => (winner, other),
        _ => panic!("one initializer must win; infrastructure failure is not a valid mismatch"),
    };
    assert_eq!(
        store
            .load_or_initialize_oidc_identity_policy(&definition)
            .await
            .unwrap(),
        winner
    );
    assert_eq!(counts(&pool).await, (1, 1, 0, 0, 0));
}

async fn initial_gate(pool: &PgPool) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5601)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION hold_initial_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(5601); RETURN NEW; END $$; CREATE TRIGGER hold_initial_insert BEFORE INSERT ON auth_oauth_connections FOR EACH ROW EXECUTE FUNCTION hold_initial_insert();").execute(pool).await.unwrap();
    gate
}
async fn observe_initial_inserts(pool: &PgPool) {
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: independent initial-insert observer");
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%INSERT INTO auth_oauth_connections%'")
                .fetch_one(&observer).await.expect("test infrastructure: observe both initial inserts");
            if count==2 {break;}
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: both initializers did not reach insert after absent reads");
    observer.close().await;
}
