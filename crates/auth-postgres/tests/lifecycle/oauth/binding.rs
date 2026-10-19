use super::setup::{Fixture, connection, copy_proof};
use auth_core::{Error, OAuthCallback, OAuthPurpose, OAuthTransactionRepository, Secret};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn browser_bound_single_use_state_does_not_create_identity(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.start().await;
    let hashes: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT state_hash,browser_hash,nonce_hash,pkce_hash FROM auth_oauth_transactions",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(
        hashes.0 == start.state.verifier()
            && hashes.1 == f.browser.verifier()
            && hashes.2 == start.proof.nonce().verifier()
            && hashes.3 == start.proof.pkce_verifier().verifier()
    );
    let replay = f.request(&start, OAuthPurpose::SignIn);
    let expected_nonce = start.proof.nonce().verifier();
    let expected_pkce = start.proof.pkce_verifier().verifier();
    let exchange = f
        .flow
        .consume(
            &f.intent(OAuthPurpose::SignIn),
            &start.state,
            start.proof,
            OAuthCallback {
                redirect: f.connection.redirect(),
                issuer: Some(f.connection.issuer()),
            },
        )
        .await
        .unwrap();
    assert!(exchange.proof().nonce().verifier() == expected_nonce);
    assert!(exchange.proof().pkce_verifier().verifier() == expected_pkce);
    assert_eq!(exchange.expires_us(), start.expires_us);
    assert_eq!(f.pending().await, 0);
    assert!(matches!(
        f.store.consume_oauth(&replay).await,
        Err(Error::Unauthorized)
    ));
    let facts: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit)")
        .fetch_one(&f.pool).await.unwrap();
    assert_eq!(facts, (0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn wrong_state_browser_nonce_pkce_and_purpose_preserve_valid_control(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.start().await;
    for dimension in 0..5 {
        let mut wrong = f.request(&start, OAuthPurpose::SignIn);
        match dimension {
            0 => wrong.state = Secret::generate().unwrap().verifier(),
            1 => wrong.browser = Secret::generate().unwrap().verifier(),
            2 => wrong.nonce = Secret::generate().unwrap().verifier(),
            3 => wrong.pkce = Secret::generate().unwrap().verifier(),
            _ => {
                wrong.purpose = OAuthPurpose::Link {
                    user: Uuid::new_v4(),
                    session: [0; 32],
                }
            }
        }
        assert!(matches!(
            f.store.consume_oauth(&wrong).await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(f.pending().await, 1);
    }
    f.store
        .consume_oauth(&f.request(&start, OAuthPurpose::SignIn))
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn wrong_realm_connection_and_client_cannot_consume_state(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.start().await;
    let other_realm = Uuid::new_v4();
    f.store.ensure_realm(other_realm).await.unwrap();
    for (realm, id, client) in [
        (f.connection.realm(), Uuid::new_v4(), f.connection.client()),
        (
            f.connection.realm(),
            f.connection.connection(),
            Uuid::new_v4(),
        ),
        (
            other_realm,
            f.connection.connection(),
            f.connection.client(),
        ),
    ] {
        let other = connection(realm, id, client);
        // Different URI is required even across realms; an aliased callback is unsafe.
        let other = auth_core::OAuthConnection::new(
            realm,
            id,
            client,
            other.issuer(),
            other.provider_client(),
            &format!("https://app.example/other/{realm}/{id}/{client}"),
            other.defense(),
        )
        .unwrap();
        let other = f.store.configure_oauth_connection(&other).await.unwrap();
        let mut wrong = f.request(&start, OAuthPurpose::SignIn);
        wrong.configuration = other;
        assert!(matches!(
            f.store.consume_oauth(&wrong).await,
            Err(Error::Unauthorized)
        ));
    }
    f.store
        .consume_oauth(&f.request(&start, OAuthPurpose::SignIn))
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn actual_callback_issuer_and_dedicated_route_are_checked_before_exchange(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.start().await;
    for (redirect, issuer) in [
        (f.connection.redirect(), None),
        (f.connection.redirect(), Some("https://attacker.example")),
        ("https://app.example/wrong", Some(f.connection.issuer())),
    ] {
        assert!(matches!(
            f.flow
                .consume(
                    &f.intent(OAuthPurpose::SignIn),
                    &start.state,
                    copy_proof(&start.proof),
                    OAuthCallback { redirect, issuer }
                )
                .await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(f.pending().await, 1);
    }
    f.flow
        .cancel(&f.intent(OAuthPurpose::SignIn), &start.state, &start.proof)
        .await
        .unwrap();
    assert_eq!(f.pending().await, 0);
    assert!(matches!(
        f.store
            .consume_oauth(&f.request(&start, OAuthPurpose::SignIn))
            .await,
        Err(Error::Unauthorized)
    ));
}
