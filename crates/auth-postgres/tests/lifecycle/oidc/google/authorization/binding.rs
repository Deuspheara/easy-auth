use super::super::setup::Fixture;
use super::setup::*;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::{Arc, atomic::Ordering};
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_authorization_refuses_mixed_sources_and_other_purposes_before_admission(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone(), false, OidcJitPolicy::Allow).await;
    let other = Fixture::new(pool, true, OidcJitPolicy::Allow).await;
    assert!(matches!(
        GoogleAuthorization::new(Arc::new(other.flow()), f.google.clone()),
        Err(Error::InvalidInput)
    ));
    let service = service(&f);
    assert_eq!(service.configuration(), f.policy.configuration());
    let browser = Secret::generate().unwrap();
    let owner = Uuid::new_v4();
    for purpose in [
        OAuthPurpose::Link {
            user: owner,
            session: browser.verifier(),
        },
        OAuthPurpose::DeleteProviderAccount {
            user: owner,
            session: browser.verifier(),
        },
    ] {
        assert!(matches!(
            service
                .begin(&OAuthIntent {
                    browser: &browser,
                    source: "owned-google-postgres",
                    purpose
                })
                .await,
            Err(Error::Unauthorized)
        ));
    }
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(other.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(f.provider.document_gets.load(Ordering::SeqCst), 0);
    let a = initiated(&f, &service, json!({})).await;
    let completion = finish(&f, &service, &a, None).await.unwrap();
    let GoogleAuthorizationCompletion::Verified(identity) = &completion else {
        panic!("signed control");
    };
    assert!(
        identity.expires_us() <= a.cap,
        "original transaction cap retained"
    );
    assert_eq!(identity.authenticated_at(), None, "no inferred freshness");
    assert_eq!(
        f.facts().await,
        (0, 0, 0, 0, 0),
        "verification itself grants no local authority"
    );
    commit(&f, completion).await;
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert!(matches!(
        finish(&f, &service, &a, None).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_callback_binding_precedes_exchange_or_denial_cancellation(pool: PgPool) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let service = service(&f);
    for error in [None, Some("access_denied"), Some("server_error")] {
        let a = initiated(&f, &service, json!({})).await;
        let wrong = Secret::generate().unwrap();
        assert!(matches!(
            service
                .finish(
                    &a.intent(),
                    &wrong,
                    a.proof(),
                    f.policy.configuration().redirect(),
                    response(&a, error)
                )
                .await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            service
                .finish(
                    &a.intent(),
                    &a.start.state,
                    a.proof(),
                    "https://app.example/wrong",
                    response(&a, error)
                )
                .await,
            Err(Error::Unauthorized)
        ));
        for intent in [
            OAuthIntent {
                browser: &wrong,
                source: "owned-google-postgres",
                purpose: OAuthPurpose::SignIn,
            },
            OAuthIntent {
                browser: &a.browser,
                source: "owned-google-postgres",
                purpose: OAuthPurpose::Link {
                    user: Uuid::new_v4(),
                    session: wrong.verifier(),
                },
            },
        ] {
            assert!(matches!(
                service
                    .finish(
                        &intent,
                        &a.start.state,
                        a.proof(),
                        f.policy.configuration().redirect(),
                        response(&a, error)
                    )
                    .await,
                Err(Error::Unauthorized)
            ));
            assert!(matches!(
                service
                    .cancel(&intent, &a.start.state, &a.start.proof)
                    .await,
                Err(Error::Unauthorized)
            ));
        }
        for wrong_nonce in [true, false] {
            let proof = || {
                OAuthBrowserProof::parse(
                    if wrong_nonce {
                        wrong.expose()
                    } else {
                        a.start.proof.nonce().expose()
                    }
                    .to_owned(),
                    if wrong_nonce {
                        a.start.proof.pkce_verifier().expose()
                    } else {
                        wrong.expose()
                    }
                    .to_owned(),
                )
                .unwrap()
            };
            assert!(matches!(
                service
                    .finish(
                        &a.intent(),
                        &a.start.state,
                        proof(),
                        f.policy.configuration().redirect(),
                        response(&a, error)
                    )
                    .await,
                Err(Error::Unauthorized)
            ));
            assert!(matches!(
                service.cancel(&a.intent(), &a.start.state, &proof()).await,
                Err(Error::Unauthorized)
            ));
        }
        assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
        assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
        if error.is_none() {
            service
                .cancel(&a.intent(), &a.start.state, &a.start.proof)
                .await
                .unwrap();
        } else {
            let completed = finish(&f, &service, &a, error).await.unwrap();
            match completed {
                GoogleAuthorizationCompletion::Denied => assert_eq!(error, Some("access_denied")),
                GoogleAuthorizationCompletion::ProviderFailure => {
                    assert_eq!(error, Some("server_error"))
                }
                GoogleAuthorizationCompletion::Verified(_) => panic!("denial must not verify"),
            }
        }
        assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
        assert!(matches!(
            finish(&f, &service, &a, None).await,
            Err(Error::Unauthorized)
        ));
    }
    let a = initiated(&f, &service, json!({})).await;
    // Network source is abuse admission, not an authentication credential.
    // Roaming must preserve the actual provider/browser/private-proof bindings.
    let roaming_source = "owned-google-roaming";
    let roaming = OAuthIntent {
        browser: &a.browser,
        source: roaming_source,
        purpose: OAuthPurpose::SignIn,
    };
    let completion = service
        .finish(
            &roaming,
            &a.start.state,
            a.proof(),
            f.policy.configuration().redirect(),
            response(&a, None),
        )
        .await
        .unwrap();
    commit(&f, completion).await;
    let budgets: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_oauth_admission WHERE realm_id=$1 AND dimension='consume_source' AND key_hash=sha256(sha256(convert_to($2,'UTF8')))")
        .bind(f.realm()).bind(roaming_source).fetch_one(&f.pool).await.expect("test infrastructure: independent network-source admission observation");
    assert_eq!(budgets, 1, "roaming still spends its own source budget");
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_concurrent_callbacks_have_one_exchange_and_no_automatic_commit(
    pool: PgPool,
) {
    let f = Fixture::new(pool, true, OidcJitPolicy::Allow).await;
    let service = service(&f);
    let a = initiated(&f, &service, json!({})).await;
    let (left, right) = tokio::join!(
        finish(&f, &service, &a, None),
        finish(&f, &service, &a, None)
    );
    let completion = match (left, right) {
        (Ok(value), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(value)) => value,
        _ => panic!("one actual callback and one replay denial required"),
    };
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    commit(&f, completion).await;
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}
