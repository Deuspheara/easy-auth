use super::super::super::{session_age::setup::selected, setup::Fixture};
use super::super::setup::response;
use super::setup::*;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::{Arc, atomic::Ordering};
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_deletion_constructor_and_purpose_reject_before_admission(pool: PgPool) {
    let f = Fixture::new(pool.clone(), false, OidcJitPolicy::Allow).await;
    let other = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    assert!(matches!(
        GoogleAccountDeletionAuthorization::new(Arc::new(other.flow()), Arc::new(selected(&f))),
        Err(Error::InvalidInput)
    ));
    let service = service(&f);
    let browser = Secret::generate().unwrap();
    for purpose in [
        OAuthPurpose::SignIn,
        OAuthPurpose::Link {
            user: Uuid::new_v4(),
            session: browser.verifier(),
        },
    ] {
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-google-managed-deletion",
            purpose,
        };
        assert!(matches!(
            service.begin(&intent).await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            service
                .cancel(
                    &intent,
                    &browser,
                    &OAuthBrowserProof::parse(
                        browser.expose().to_owned(),
                        browser.expose().to_owned()
                    )
                    .unwrap()
                )
                .await,
            Err(Error::Unauthorized)
        ));
    }
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(f.provider.document_gets.load(Ordering::SeqCst), 0);
    let (user, session) = account(&f).await;
    let a = initiated(
        &f,
        &service,
        &user,
        &session,
        json!({"auth_time":now(&f).await}),
    )
    .await;
    remove(
        &f,
        finish(&f, &service, &a, &user, &session, None)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_deletion_codes_and_errors_require_original_private_binding(pool: PgPool) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let service = service(&f);
    let (user, session) = account(&f).await;
    for error in [None, Some("access_denied"), Some("server_error")] {
        let a = initiated(
            &f,
            &service,
            &user,
            &session,
            json!({"auth_time":now(&f).await}),
        )
        .await;
        let wrong = Secret::generate().unwrap();
        let mut wrong_user = user.clone();
        wrong_user.id = Uuid::new_v4();
        let expected = intent(&a.browser, &user, &session);
        // Every rejected variant must leave the original operation usable, including errors.
        for bad in [
            intent(&wrong, &user, &session),
            intent(&a.browser, &wrong_user, &session),
            intent(&a.browser, &user, &wrong),
            a.intent(),
            OAuthIntent {
                browser: &a.browser,
                source: "owned-google-managed-deletion",
                purpose: OAuthPurpose::Link {
                    user: user.id,
                    session: session.verifier(),
                },
            },
        ] {
            assert!(matches!(
                service
                    .finish(
                        &bad,
                        &a.start.state,
                        a.proof(),
                        f.policy.configuration().redirect(),
                        response(&a, error)
                    )
                    .await,
                Err(Error::Unauthorized)
            ));
            assert!(matches!(
                service.cancel(&bad, &a.start.state, &a.start.proof).await,
                Err(Error::Unauthorized)
            ));
        }
        for (state, redirect) in [
            (&wrong, f.policy.configuration().redirect()),
            (&a.start.state, "https://app.example/wrong"),
        ] {
            assert!(matches!(
                service
                    .finish(&expected, state, a.proof(), redirect, response(&a, error))
                    .await,
                Err(Error::Unauthorized)
            ));
        }
        for nonce in [true, false] {
            let proof = || {
                OAuthBrowserProof::parse(
                    if nonce {
                        wrong.expose()
                    } else {
                        a.start.proof.nonce().expose()
                    }
                    .to_owned(),
                    if nonce {
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
                        &expected,
                        &a.start.state,
                        proof(),
                        f.policy.configuration().redirect(),
                        response(&a, error)
                    )
                    .await,
                Err(Error::Unauthorized)
            ));
            assert!(matches!(
                service.cancel(&expected, &a.start.state, &proof()).await,
                Err(Error::Unauthorized)
            ));
        }
        assert_eq!(f.facts().await, (1, 1, 1, 1, 1));
        assert_eq!(
            f.provider.posts.load(Ordering::SeqCst),
            1,
            "only original account sign-in reached provider"
        );
        if error.is_none() {
            service
                .cancel(&expected, &a.start.state, &a.start.proof)
                .await
                .unwrap();
        } else {
            assert!(matches!(
                (
                    error,
                    finish(&f, &service, &a, &user, &session, error)
                        .await
                        .unwrap()
                ),
                (Some("access_denied"), GoogleAuthorizationCompletion::Denied)
                    | (
                        Some("server_error"),
                        GoogleAuthorizationCompletion::ProviderFailure
                    )
            ));
        }
        assert!(matches!(
            finish(&f, &service, &a, &user, &session, None).await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(
            f.store
                .authenticate(f.realm(), session.verifier())
                .await
                .unwrap(),
            user
        );
    }
    let a = initiated(
        &f,
        &service,
        &user,
        &session,
        json!({"auth_time":now(&f).await}),
    )
    .await;
    let result = finish(&f, &service, &a, &user, &session, None)
        .await
        .unwrap();
    let GoogleAuthorizationCompletion::Verified(identity) = &result else {
        panic!("signed positive control")
    };
    assert!(identity.expires_us() <= a.cap);
    assert_eq!(
        f.facts().await,
        (1, 1, 1, 1, 0),
        "verified proof alone grants no deletion or session"
    );
    remove(&f, result).await.unwrap();
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
}
