use super::setup::Fixture;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test(migrations = "./migrations")]
async fn wrong_apple_browser_private_proof_state_and_actual_route_leave_valid_work_intact(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let a = f.prepare("subject", json!({})).await;
    let foreign = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &foreign,
        ..a.intent()
    };
    assert!(matches!(
        f.flow
            .finish(
                &intent,
                &a.start.transaction.state,
                a.proof(),
                f.policy.configuration().redirect(),
                a.response(None)
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let proof = OAuthBrowserProof::parse(
        foreign.expose().to_owned(),
        a.start
            .transaction
            .proof
            .pkce_verifier()
            .expose()
            .to_owned(),
    )
    .unwrap();
    assert!(matches!(
        f.flow
            .finish(
                &a.intent(),
                &a.start.transaction.state,
                proof,
                f.policy.configuration().redirect(),
                a.response(None)
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow
            .finish(
                &a.intent(),
                &foreign,
                a.proof(),
                f.policy.configuration().redirect(),
                a.response(None)
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow
            .finish(
                &a.intent(),
                &a.start.transaction.state,
                a.proof(),
                "https://foreign.example/callback",
                a.response(None)
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    f.signin(&a).await.unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn apple_denial_cancels_only_bound_operation_without_token_io(pool: PgPool) {
    let f = Fixture::new(
        pool,
        AppleClientType::Native(AppleNonceEncoding::Plain),
        OidcJitPolicy::Allow,
    )
    .await;
    let a = f.prepare("subject", json!({})).await;
    let result = f
        .flow
        .finish(
            &a.intent(),
            &a.start.transaction.state,
            a.proof(),
            f.policy.configuration().redirect(),
            a.response(Some("user_cancelled_authorize")),
        )
        .await
        .unwrap();
    assert!(matches!(result, AppleAuthorizationCompletion::Denied));
    assert!(matches!(f.signin(&a).await, Err(Error::Unauthorized)));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn wrong_signed_apple_claims_are_not_infrastructure_failures_and_valid_controls_commit(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    for bad in [
        json!({"nonce":Secret::generate().unwrap().expose()}),
        json!({"aud":"com.other.app"}),
        json!({"iss":"https://foreign.example"}),
        json!({"email_verified":"TRUE"}),
    ] {
        let a = f.prepare("subject", bad).await;
        assert!(matches!(f.signin(&a).await, Err(Error::Unauthorized)));
    }
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 4);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    let valid = f
        .prepare(
            "subject",
            json!({"email":"owned@privaterelay.appleid.com","email_verified":"true"}),
        )
        .await;
    f.signin(&valid).await.unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}
