use super::{
    provider::ISSUER,
    setup::{Attempt, Fixture},
};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

fn query(a: &Attempt, error: Option<&str>) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("state", a.start.state.expose())
        .append_pair("iss", ISSUER);
    match error {
        Some(error) => {
            form.append_pair("error", error)
                .append_pair("error_description", "private-provider-detail");
        }
        None => {
            form.append_pair("code", a.code.expose())
                .append_pair("scope", "openid email")
                .append_pair("authuser", "0")
                .append_pair("hd", "untrusted.example")
                .append_pair("prompt", "consent");
        }
    }
    form.finish()
}

#[sqlx::test(migrations = "./migrations")]
async fn google_decoded_callback_preserves_private_binding_and_one_use_exchange(pool: PgPool) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let a = f.prepare("callback-subject", json!({}), None).await;
    let raw = query(&a, None);
    let response = GoogleAuthorizationResponse::parse(&raw).unwrap();
    assert_eq!(response.state().verifier(), a.start.state.verifier());
    assert!(matches!(
        response.outcome(),
        GoogleAuthorizationOutcome::Code(_)
    ));
    assert_eq!(
        f.facts().await,
        (0, 0, 0, 0, 1),
        "decoding grants and consumes nothing"
    );
    let wrong = OAuthBrowserProof::parse(
        Secret::generate().unwrap().expose().to_owned(),
        Secret::generate().unwrap().expose().to_owned(),
    )
    .unwrap();
    assert!(matches!(
        f.flow()
            .consume(
                &a.intent(),
                response.state(),
                wrong,
                OAuthCallback {
                    redirect: f.policy.configuration().redirect(),
                    issuer: Some(response.issuer())
                }
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    let exchange = f
        .flow()
        .consume(
            &a.intent(),
            response.state(),
            a.proof(),
            OAuthCallback {
                redirect: f.policy.configuration().redirect(),
                issuer: Some(response.issuer()),
            },
        )
        .await
        .unwrap();
    let GoogleAuthorizationOutcome::Code(code) = response.into_outcome() else {
        panic!("owned valid callback must carry a code");
    };
    let identity = f.google.exchange(exchange, code).await.unwrap();
    let (owner, session) = f.sign_in(f.policy.map(identity).unwrap()).await.unwrap();
    assert!(owner.email.is_none());
    assert_eq!(
        f.store
            .authenticate(f.realm(), session.verifier())
            .await
            .unwrap(),
        owner
    );
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    let replay = GoogleAuthorizationResponse::parse(&raw).unwrap();
    assert!(matches!(
        f.flow()
            .consume(
                &a.intent(),
                replay.state(),
                a.proof(),
                OAuthCallback {
                    redirect: f.policy.configuration().redirect(),
                    issuer: Some(replay.issuer())
                }
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn google_decoded_denial_and_failure_require_bound_cancellation_and_no_exchange(
    pool: PgPool,
) {
    let f = Fixture::new(pool, true, OidcJitPolicy::Allow).await;
    for error in ["access_denied", "server_error"] {
        let a = f.prepare("denied-subject", json!({}), None).await;
        let raw = query(&a, Some(error));
        let missing_issuer = raw.replace("iss=https%3A%2F%2Faccounts.google.com&", "");
        assert!(matches!(
            GoogleAuthorizationResponse::parse(&missing_issuer),
            Err(Error::Unauthorized)
        ));
        let response = GoogleAuthorizationResponse::parse(&raw).unwrap();
        assert!(!matches!(
            response.outcome(),
            GoogleAuthorizationOutcome::Code(_)
        ));
        assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
        let foreign = Secret::generate().unwrap();
        let wrong_browser = OAuthIntent {
            browser: &foreign,
            source: "owned-google-postgres",
            purpose: OAuthPurpose::SignIn,
        };
        assert!(matches!(
            f.flow()
                .cancel(&wrong_browser, response.state(), &a.start.proof)
                .await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
        f.flow()
            .cancel(&a.intent(), response.state(), &a.start.proof)
            .await
            .unwrap();
        match response.into_outcome() {
            GoogleAuthorizationOutcome::Denied => assert_eq!(error, "access_denied"),
            GoogleAuthorizationOutcome::ProviderFailure => assert_eq!(error, "server_error"),
            GoogleAuthorizationOutcome::Code(_) => panic!("error cannot become a token exchange"),
        }
        assert!(matches!(f.verified(&a).await, Err(Error::Unauthorized)));
        assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 0);
    let (owner, _) = f
        .sign_in(f.mapped("positive-control", json!({})).await)
        .await
        .unwrap();
    assert!(owner.email.is_none());
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
}
