use super::setup::*;
use auth_core::*;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn initial_policy_write_failure_is_unavailable_and_rolls_back_registry(pool: PgPool) {
    let (store, input) = empty(pool.clone()).await;
    sqlx::raw_sql("CREATE FUNCTION fail_startup_policy() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned startup storage fault'; END $$; CREATE TRIGGER fail_startup_policy BEFORE INSERT ON auth_oidc_identity_policies FOR EACH ROW EXECUTE FUNCTION fail_startup_policy();").execute(&pool).await.unwrap();
    let before = snapshot(&pool).await;
    assert!(
        matches!(
            store.load_or_initialize_oidc_identity_policy(&input).await,
            Err(Error::Unavailable)
        ),
        "storage failure cannot count as an expected authorization denial"
    );
    assert!(before == snapshot(&pool).await);
    assert_eq!(counts(&pool).await, (0, 0, 0, 0, 0));
    sqlx::query("DROP TRIGGER fail_startup_policy ON auth_oidc_identity_policies")
        .execute(&pool)
        .await
        .unwrap();
    store
        .load_or_initialize_oidc_identity_policy(&input)
        .await
        .unwrap();
    assert_eq!(counts(&pool).await, (1, 1, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_registry_and_corrupt_revision_are_not_authentication_rejections(pool: PgPool) {
    let (store, input) = empty(pool.clone()).await;
    let actual = store
        .load_or_initialize_oidc_identity_policy(&input)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE auth_oidc_identity_policies RENAME TO owned_hidden_identity_policies")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        store.load_or_initialize_oidc_identity_policy(&input).await,
        Err(Error::Unavailable)
    ));
    sqlx::query("ALTER TABLE owned_hidden_identity_policies RENAME TO auth_oidc_identity_policies")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        store
            .load_or_initialize_oidc_identity_policy(&input)
            .await
            .unwrap(),
        actual
    );
    let c = actual.configuration();
    sqlx::query("UPDATE auth_oauth_connections SET revision=$4 WHERE realm_id=$1 AND id=$2 AND client_id=$3")
        .bind(c.realm()).bind(c.connection()).bind(c.client()).bind(Uuid::nil()).execute(&pool).await.unwrap();
    let before = snapshot(&pool).await;
    assert!(matches!(
        store.load_or_initialize_oidc_identity_policy(&input).await,
        Err(Error::Unavailable)
    ));
    assert!(
        before == snapshot(&pool).await,
        "a malformed stored revision must not be repaired into new authority"
    );
}
