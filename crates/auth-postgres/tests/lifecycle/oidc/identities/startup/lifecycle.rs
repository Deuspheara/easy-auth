use super::super::setup::Fixture;
use super::setup::*;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn initial_creation_is_atomic_fresh_and_restarts_are_read_only(pool: PgPool) {
    let (store, input) = empty(pool.clone()).await;
    let actual = store
        .load_or_initialize_oidc_identity_policy(&input)
        .await
        .unwrap();
    assert_ne!(
        actual.configuration().revision(),
        input.configuration().revision()
    );
    assert_eq!(counts(&pool).await, (1, 1, 0, 0, 0));
    let before = snapshot(&pool).await;
    // Tripwires prove an unchanged load performs no registry/policy DML.
    sqlx::raw_sql("CREATE FUNCTION reject_startup_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned startup insert probe'; END $$; CREATE TRIGGER reject_startup_insert BEFORE INSERT OR UPDATE OR DELETE ON auth_oauth_connections FOR EACH ROW EXECUTE FUNCTION reject_startup_insert(); CREATE TRIGGER reject_startup_policy_write BEFORE INSERT OR UPDATE OR DELETE ON auth_oidc_identity_policies FOR EACH ROW EXECUTE FUNCTION reject_startup_insert();").execute(&pool).await.unwrap();
    for _ in 0..3 {
        assert_eq!(
            store
                .load_or_initialize_oidc_identity_policy(&input)
                .await
                .unwrap(),
            actual
        );
    }
    assert!(
        before == snapshot(&pool).await,
        "unchanged startup must not mutate configuration or authority"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn restart_preserves_real_session_and_original_pending_context(pool: PgPool) {
    let mut f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (user, session) = f
        .sign_in
        .finish(f.mapped("owner", json!({})).await)
        .await
        .unwrap();
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "startup-control",
        purpose: OAuthPurpose::SignIn,
    };
    let flow = OAuthTransactions::new(f.policy.configuration().clone(), f.store.clone());
    let pending = flow.begin(&intent).await.unwrap();
    let original = f.policy.clone();
    let before = snapshot(&f.pool).await;
    f.load_at_startup().await.unwrap();
    assert_eq!(f.policy, original);
    assert!(
        before == snapshot(&f.pool).await,
        "loading cannot cancel pending proof, touch sessions or rewrite audit"
    );
    assert_eq!(
        f.store
            .authenticate(f.realm(), session.verifier())
            .await
            .unwrap()
            .id,
        user.id
    );
    let c = f.policy.configuration();
    flow.consume(
        &intent,
        &pending.state,
        pending.proof,
        OAuthCallback {
            redirect: c.redirect(),
            issuer: Some(c.issuer()),
        },
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn recreating_removed_registry_never_revives_old_verified_context(pool: PgPool) {
    let mut f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let old = f.mapped("owner", json!({})).await;
    let revision = f.policy.configuration().revision();
    let c = f.policy.configuration();
    sqlx::query("DELETE FROM auth_oauth_connections WHERE realm_id=$1 AND id=$2 AND client_id=$3")
        .bind(c.realm())
        .bind(c.connection())
        .bind(c.client())
        .execute(&f.pool)
        .await
        .unwrap();
    f.load_at_startup().await.unwrap();
    assert_ne!(f.policy.configuration().revision(), revision);
    assert!(matches!(
        f.sign_in.finish(old).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.sign_in
        .finish(f.mapped("owner", json!({})).await)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn registry_keys_are_realm_and_local_client_scoped_and_callback_stays_unique(pool: PgPool) {
    let (store, first) = empty(pool.clone()).await;
    let c = first.configuration();
    let foreign = Uuid::new_v4();
    store.ensure_realm(foreign).await.unwrap();
    let definitions = [
        first.clone(),
        definition(foreign, c.connection(), c.client()),
        definition(c.realm(), c.connection(), Uuid::new_v4()),
    ];
    let mut revisions = Vec::new();
    for input in &definitions {
        let actual = store
            .load_or_initialize_oidc_identity_policy(input)
            .await
            .unwrap();
        assert!(!revisions.contains(&actual.configuration().revision()));
        revisions.push(actual.configuration().revision());
        assert_eq!(
            store
                .load_or_initialize_oidc_identity_policy(input)
                .await
                .unwrap(),
            actual
        );
    }
    let collision = OAuthConnection::new(
        foreign,
        Uuid::new_v4(),
        Uuid::new_v4(),
        c.issuer(),
        c.provider_client(),
        c.redirect(),
        c.defense(),
    )
    .unwrap();
    let collision =
        OidcIdentityPolicy::new(collision, &[c.issuer()], first.display_name_claim()).unwrap();
    let before = snapshot(&pool).await;
    assert!(
        matches!(
            store
                .load_or_initialize_oidc_identity_policy(&collision)
                .await,
            Err(Error::Unavailable)
        ),
        "global callback uniqueness is a storage constraint, never successful authority or a fake authentication rejection"
    );
    assert!(before == snapshot(&pool).await);
    assert_eq!(counts(&pool).await, (3, 3, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn old_startup_input_loads_current_revision_without_restoring_old_sessions(pool: PgPool) {
    let mut f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (user, old_session) = f
        .sign_in
        .finish(f.mapped("owner", json!({})).await)
        .await
        .unwrap();
    let old_proof = f.mapped("owner", json!({})).await;
    let old_input = f.policy.clone();
    let current = f
        .store
        .configure_oidc_identity_policy(&old_input)
        .await
        .unwrap();
    let before = snapshot(&f.pool).await;
    assert_ne!(
        current.configuration().revision(),
        old_input.configuration().revision()
    );
    assert_eq!(
        f.store
            .load_or_initialize_oidc_identity_policy(&old_input)
            .await
            .unwrap(),
        current
    );
    assert!(before == snapshot(&f.pool).await);
    assert!(matches!(
        f.store
            .authenticate(f.realm(), old_session.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.sign_in.finish(old_proof).await,
        Err(Error::Unauthorized)
    ));
    f.load_at_startup().await.unwrap();
    let (same_user, session) = f
        .sign_in
        .finish(f.mapped("owner", json!({})).await)
        .await
        .unwrap();
    assert_eq!(same_user.id, user.id);
    f.store
        .authenticate(f.realm(), session.verifier())
        .await
        .unwrap();
}
