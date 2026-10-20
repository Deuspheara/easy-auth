use super::super::setup::Fixture;
use super::setup::*;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn full_definition_mismatch_cannot_reconfigure_or_cancel_existing_authority(pool: PgPool) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    f.sign_in
        .finish(f.mapped("owner", json!({})).await)
        .await
        .unwrap();
    let c = f.policy.configuration();
    let browser = Secret::generate().unwrap();
    let flow = OAuthTransactions::new(c.clone(), f.store.clone());
    let intent = OAuthIntent {
        browser: &browser,
        source: "startup-control",
        purpose: OAuthPurpose::SignIn,
    };
    let pending = flow.begin(&intent).await.unwrap();
    let before = snapshot(&f.pool).await;
    for change in 0..7 {
        let issuer = if change == 0 {
            "https://other.example"
        } else {
            c.issuer()
        };
        let provider_client = if change == 1 {
            "another-client"
        } else {
            c.provider_client()
        };
        let redirect = if change == 2 {
            "https://app.example/other-callback"
        } else {
            c.redirect()
        };
        let defense = if change == 3 {
            OAuthMixupDefense::DedicatedRedirect
        } else {
            c.defense()
        };
        let allowed = if change == 4 {
            vec![issuer, "https://another-tenant.example"]
        } else {
            vec![issuer]
        };
        let claim = if change == 5 {
            OidcDisplayNameClaim::Subject
        } else {
            f.policy.display_name_claim()
        };
        let jit = if change == 6 {
            OidcJitPolicy::Deny
        } else {
            f.policy.jit()
        };
        let input = OAuthConnection::new(
            c.realm(),
            c.connection(),
            c.client(),
            issuer,
            provider_client,
            redirect,
            defense,
        )
        .unwrap();
        let input = OidcIdentityPolicy::new(input, &allowed, claim)
            .unwrap()
            .with_jit(jit);
        assert!(
            matches!(
                f.store
                    .load_or_initialize_oidc_identity_policy(&input)
                    .await,
                Err(Error::Unauthorized)
            ),
            "startup mismatch must fail without becoming an administrative update"
        );
        assert!(
            before == snapshot(&f.pool).await,
            "mismatch changed registry, pending proof or account authority"
        );
    }
    let loaded = f
        .store
        .load_or_initialize_oidc_identity_policy(&f.policy)
        .await
        .unwrap();
    assert_eq!(loaded, f.policy);
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
async fn startup_cannot_adopt_generic_oauth_or_upgrade_its_existing_exchange(pool: PgPool) {
    let (store, input) = empty(pool.clone()).await;
    let c = store
        .configure_oauth_connection(input.configuration())
        .await
        .unwrap();
    let flow = OAuthTransactions::new(c.clone(), store.clone());
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "generic-control",
        purpose: OAuthPurpose::SignIn,
    };
    let pending = flow.begin(&intent).await.unwrap();
    let before = snapshot(&pool).await;
    assert!(matches!(
        store.load_or_initialize_oidc_identity_policy(&input).await,
        Err(Error::Unauthorized)
    ));
    assert!(
        before == snapshot(&pool).await,
        "generic OAuth must retain its original definition and pending context without gaining policy"
    );
    assert_eq!(counts(&pool).await, (1, 0, 0, 0, 1));
    let exchange = flow
        .consume(
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
    assert_eq!(exchange.configuration().revision(), c.revision());
    // Explicit administrative adoption is a separate operation and rotates the
    // source before local identity authority becomes available.
    let configured = store.configure_oidc_identity_policy(&input).await.unwrap();
    assert_ne!(configured.configuration().revision(), c.revision());
    assert!(matches!(
        store.check_oidc_exchange(&exchange).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn disabled_source_is_preserved_and_old_verified_proof_stays_revoked(pool: PgPool) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let old = f.mapped("owner", json!({})).await;
    let c = f.policy.configuration();
    f.store
        .disable_oauth_connection(c.realm(), c.connection(), c.client())
        .await
        .unwrap();
    let before = snapshot(&f.pool).await;
    assert!(matches!(
        f.store
            .load_or_initialize_oidc_identity_policy(&f.policy)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(
        before == snapshot(&f.pool).await,
        "loading cannot rotate or clear disable"
    );
    assert!(matches!(
        f.sign_in.finish(old).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_policy_revision_is_not_repaired_to_match_enabled_configuration(pool: PgPool) {
    let mut f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let old = f.mapped("owner", json!({})).await;
    let old_input = f.policy.clone();
    // Generic OAuth administration deliberately changes only the connection;
    // the retained identity policy is now stale and must not be auto-adopted.
    let connection = f
        .store
        .configure_oauth_connection(old_input.configuration())
        .await
        .unwrap();
    f.store.check_oidc_connection(&connection).await.unwrap();
    let before = snapshot(&f.pool).await;
    assert!(matches!(
        f.store
            .load_or_initialize_oidc_identity_policy(&old_input)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(
        before == snapshot(&f.pool).await,
        "startup cannot update a stale policy revision to confer authority"
    );
    assert!(matches!(
        f.sign_in.finish(old).await,
        Err(Error::Unauthorized)
    ));
    f.reconfigure(OidcJitPolicy::Allow).await;
    f.load_at_startup().await.unwrap();
    f.sign_in
        .finish(f.mapped("owner", json!({})).await)
        .await
        .unwrap();
}
