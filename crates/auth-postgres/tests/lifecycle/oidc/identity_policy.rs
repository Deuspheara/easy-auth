use super::setup::Fixture;
use auth_core::{
    Error, OAuthIntent, OAuthPurpose, OAuthTransactions, OidcConnectionRepository,
    OidcDisplayNameClaim, OidcExchangeRepository, OidcIdentityPolicy, OidcJitPolicy, Secret,
};
use sqlx::PgPool;
use uuid::Uuid;

fn policy(f: &Fixture) -> OidcIdentityPolicy {
    OidcIdentityPolicy::new(
        f.connection.clone(),
        &[f.connection.issuer(), "https://other.example/tenant"],
        OidcDisplayNameClaim::PreferredUsername,
    )
    .unwrap()
}

async fn pending(f: &Fixture) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM auth_oauth_transactions")
        .fetch_one(&f.pool)
        .await
        .expect("test infrastructure: inspect owned pending state")
}

#[sqlx::test(migrations = "./migrations")]
async fn policy_application_revises_configuration_and_cancels_prior_exchange_and_pending_state(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let old = f.exchange(OAuthPurpose::SignIn).await;
    f.store.check_oidc_exchange(&old).await.unwrap();
    let browser = Secret::generate().unwrap();
    let flow = OAuthTransactions::new(f.connection.clone(), f.store.clone());
    flow.begin(&OAuthIntent {
        browser: &browser,
        source: "policy-owned",
        purpose: OAuthPurpose::SignIn,
    })
    .await
    .unwrap();
    assert_eq!(pending(&f).await, 1);
    let input = policy(&f);
    let stored = f
        .store
        .configure_oidc_identity_policy(&input)
        .await
        .unwrap();
    assert_ne!(
        stored.configuration().revision(),
        input.configuration().revision()
    );
    assert_eq!(stored.jit(), OidcJitPolicy::Deny);
    assert_eq!(stored.allowed_issuers(), input.allowed_issuers());
    assert_eq!(
        stored.display_name_claim(),
        OidcDisplayNameClaim::PreferredUsername
    );
    let row: (Uuid, String, String, Vec<String>) = sqlx::query_as(
        "SELECT revision,jit,display_claim,allowed_issuers FROM auth_oidc_identity_policies WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3"
    ).bind(f.connection.realm()).bind(f.connection.connection()).bind(f.connection.client()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(
        row,
        (
            stored.configuration().revision(),
            "deny".into(),
            "preferred_username".into(),
            stored.allowed_issuers().to_vec()
        )
    );
    assert_eq!(pending(&f).await, 0);
    assert!(matches!(
        f.store.check_oidc_exchange(&old).await,
        Err(Error::Unauthorized)
    ));
    f.store
        .check_oidc_connection(stored.configuration())
        .await
        .unwrap();
    let facts: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit)").fetch_one(&f.pool).await.unwrap();
    assert_eq!(facts, (0, 0, 0), "policy configuration is not provisioning");
}

#[sqlx::test(migrations = "./migrations")]
async fn failing_policy_write_rolls_back_revision_pending_cancellation_and_prior_policy(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool).await;
    let original = f
        .store
        .configure_oidc_identity_policy(&policy(&f))
        .await
        .unwrap();
    f.connection = original.configuration().clone();
    let exchange = f.exchange(OAuthPurpose::SignIn).await;
    let browser = Secret::generate().unwrap();
    let flow = OAuthTransactions::new(f.connection.clone(), f.store.clone());
    flow.begin(&OAuthIntent {
        browser: &browser,
        source: "policy-rollback",
        purpose: OAuthPurpose::SignIn,
    })
    .await
    .unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_policy() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned policy failure'; END $$; CREATE TRIGGER reject_policy BEFORE INSERT OR UPDATE ON auth_oidc_identity_policies FOR EACH ROW EXECUTE FUNCTION reject_policy();").execute(&f.pool).await.unwrap();
    let changed = original.clone().with_jit(OidcJitPolicy::Allow);
    assert!(
        matches!(
            f.store.configure_oidc_identity_policy(&changed).await,
            Err(Error::Unavailable)
        ),
        "a deliberate write fault is infrastructure failure, never authorization evidence"
    );
    assert_eq!(pending(&f).await, 1);
    f.store.check_oidc_exchange(&exchange).await.unwrap();
    let row: (Uuid, String) =
        sqlx::query_as("SELECT revision,jit FROM auth_oidc_identity_policies")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(row, (original.configuration().revision(), "deny".into()));
    sqlx::query("DROP TRIGGER reject_policy ON auth_oidc_identity_policies")
        .execute(&f.pool)
        .await
        .unwrap();
    let stored = f
        .store
        .configure_oidc_identity_policy(&changed)
        .await
        .unwrap();
    assert_eq!(stored.jit(), OidcJitPolicy::Allow);
    assert_eq!(pending(&f).await, 0);
    assert!(matches!(
        f.store.check_oidc_exchange(&exchange).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_policy_application_cannot_clear_disable_and_reapplying_stale_policy_gets_new_revision(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let input = policy(&f).with_jit(OidcJitPolicy::Allow);
    let (configured, disabled) = tokio::join!(
        f.store.configure_oidc_identity_policy(&input),
        f.store.disable_oauth_connection(
            f.connection.realm(),
            f.connection.connection(),
            f.connection.client()
        ),
    );
    let stored = configured.unwrap();
    disabled.unwrap();
    let enabled: bool = sqlx::query_scalar("SELECT enabled FROM auth_oauth_connections")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert!(!enabled);
    assert!(matches!(
        f.store.check_oidc_connection(stored.configuration()).await,
        Err(Error::Unauthorized)
    ));
    let current = f
        .store
        .configure_oidc_identity_policy(&input)
        .await
        .unwrap();
    assert_ne!(
        current.configuration().revision(),
        input.configuration().revision()
    );
    assert_ne!(
        current.configuration().revision(),
        stored.configuration().revision()
    );
    assert!(matches!(
        f.store.check_oidc_connection(current.configuration()).await,
        Err(Error::Unauthorized)
    ));
    f.store
        .enable_oauth_connection(current.configuration())
        .await
        .unwrap();
    f.store
        .check_oidc_connection(current.configuration())
        .await
        .unwrap();
    assert!(matches!(
        f.store
            .enable_oauth_connection(stored.configuration())
            .await,
        Err(Error::Unauthorized)
    ));
}
