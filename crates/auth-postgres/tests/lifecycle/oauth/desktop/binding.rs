use super::super::setup::copy_proof;
use super::setup::{flow, input};
use crate::support::realm;
use auth_core::*;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn persisted_native_return_is_exact_and_cannot_be_substituted_during_consume_or_cancel(
    pool: PgPool,
) {
    let (store, realm) = realm(pool.clone()).await;
    let store = Arc::new(store);
    let c = store
        .configure_oauth_connection(&input(realm))
        .await
        .unwrap();
    let first = flow(&c, store.clone(), 49154);
    let other = flow(&c, store.clone(), 49155);
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "desktop-binding",
        purpose: OAuthPurpose::SignIn,
    };
    let start = first.begin(&intent).await.unwrap();
    let saved: String = sqlx::query_scalar(
        "SELECT redirect_uri FROM auth_oauth_transactions WHERE realm_id=$1 AND state_hash=$2",
    )
    .bind(realm)
    .bind(start.state.verifier().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(saved, first.redirect());
    assert!(matches!(
        other
            .consume(
                &intent,
                &start.state,
                copy_proof(&start.proof),
                OAuthCallback {
                    redirect: other.redirect(),
                    issuer: Some(c.issuer())
                }
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        other.cancel(&intent, &start.state, &start.proof).await,
        Err(Error::Unauthorized)
    ));
    let wrong = Secret::generate().unwrap();
    let wrong_browser = OAuthIntent {
        browser: &wrong,
        source: "desktop-binding",
        purpose: OAuthPurpose::SignIn,
    };
    assert!(matches!(
        first
            .cancel(&wrong_browser, &start.state, &start.proof)
            .await,
        Err(Error::Unauthorized)
    ));
    let (a, b) = tokio::join!(
        first.consume(
            &intent,
            &start.state,
            copy_proof(&start.proof),
            OAuthCallback {
                redirect: first.redirect(),
                issuer: Some(c.issuer())
            }
        ),
        first.consume(
            &intent,
            &start.state,
            copy_proof(&start.proof),
            OAuthCallback {
                redirect: first.redirect(),
                issuer: Some(c.issuer())
            }
        )
    );
    match (a, b) {
        (Ok(ex), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(ex)) => {
            assert_eq!(ex.redirect(), first.redirect());
            assert_eq!(ex.configuration(), &c);
        }
        _ => panic!("one return wins; storage/transport failure cannot stand in for replay denial"),
    }
    let pending = first.begin(&intent).await.unwrap();
    first
        .cancel(&intent, &pending.state, &pending.proof)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn native_profiles_keep_realm_isolation_and_reject_unreviewed_purposes_and_storage_faults(
    pool: PgPool,
) {
    let (store, realm) = realm(pool.clone()).await;
    let store = Arc::new(store);
    let c = store
        .configure_oauth_connection(&input(realm))
        .await
        .unwrap();
    let first = flow(&c, store.clone(), 49154);
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "desktop-realm",
        purpose: OAuthPurpose::SignIn,
    };
    let start = first.begin(&intent).await.unwrap();
    let (_, other_realm) = crate::support::realm(pool.clone()).await;
    // Distinct registered anchors keep global uniqueness, but the admitted
    // operation URI is identical: realm/source binding must do the isolation.
    let anchor_path = url::Url::parse(c.redirect()).unwrap();
    let other_input = OAuthConnection::with_redirect(
        other_realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        c.issuer(),
        c.provider_client(),
        OAuthRedirect::desktop_loopback("127.0.0.1:49156".parse().unwrap(), anchor_path.path())
            .unwrap(),
        c.defense(),
    )
    .unwrap()
    .with_desktop_loopback_returns()
    .unwrap();
    let other = store
        .configure_oauth_connection(&other_input)
        .await
        .unwrap();
    let foreign = flow(&other, store.clone(), 49154);
    assert_eq!(foreign.redirect(), first.redirect());
    assert!(matches!(
        foreign.cancel(&intent, &start.state, &start.proof).await,
        Err(Error::Unauthorized)
    ));
    let other_client = OAuthConnection::with_redirect(
        realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        c.issuer(),
        c.provider_client(),
        OAuthRedirect::desktop_loopback("127.0.0.1:49157".parse().unwrap(), anchor_path.path())
            .unwrap(),
        c.defense(),
    )
    .unwrap()
    .with_desktop_loopback_returns()
    .unwrap();
    let other_client = store
        .configure_oauth_connection(&other_client)
        .await
        .unwrap();
    let foreign_client = flow(&other_client, store.clone(), 49154);
    assert_eq!(foreign_client.redirect(), first.redirect());
    assert!(matches!(
        foreign_client
            .cancel(&intent, &start.state, &start.proof)
            .await,
        Err(Error::Unauthorized)
    ));
    for purpose in [
        OAuthPurpose::Link {
            user: Uuid::new_v4(),
            session: [1; 32],
        },
        OAuthPurpose::DeleteProviderAccount {
            user: Uuid::new_v4(),
            session: [1; 32],
        },
    ] {
        let wrong = OAuthIntent {
            browser: &browser,
            source: "desktop-realm",
            purpose,
        };
        assert!(matches!(
            first.begin(&wrong).await,
            Err(Error::InvalidInput)
        ));
    }
    sqlx::query("ALTER TABLE auth_oauth_transactions RENAME TO held_oauth_transactions")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        first.cancel(&intent, &start.state, &start.proof).await,
        Err(Error::Unavailable)
    ));
    sqlx::query("ALTER TABLE held_oauth_transactions RENAME TO auth_oauth_transactions")
        .execute(&pool)
        .await
        .unwrap();
    first
        .cancel(&intent, &start.state, &start.proof)
        .await
        .unwrap();
    let positive = first.begin(&intent).await.unwrap();
    first
        .consume(
            &intent,
            &positive.state,
            positive.proof,
            OAuthCallback {
                redirect: first.redirect(),
                issuer: Some(c.issuer()),
            },
        )
        .await
        .unwrap();
    let facts: (i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit),(SELECT count(*) FROM auth_oauth_transactions)")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(facts, (0, 0, 0, 0));
}
