use super::setup::*;
use auth_core::*;
use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test]
async fn another_valid_session_cannot_finish_original_intent(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    for subject in ["owned", "other"] {
        let (_, replacement) = f.another_session(subject).await;
        let switched = attempt
            .cookie
            .split("; ")
            .skip(1)
            .collect::<Vec<_>>()
            .join("; ");
        let switched = format!("__Host-auth-session={}; {switched}", replacement.expose());
        assert!(
            f.auth.authenticate(&replacement).await.is_ok(),
            "test infrastructure: switched session is genuinely valid"
        );
        assert_eq!(
            f.post("finish", attempt.callback.clone(), &switched)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(f.exists().await);
        assert_eq!(f.pending().await, 1);
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.post("finish", attempt.callback, &attempt.cookie)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
}

#[sqlx::test]
async fn sign_in_purpose_cannot_be_substituted_for_deletion(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "embedded",
        purpose: OAuthPurpose::SignIn,
    };
    let start = f.transactions.begin(&intent).await.unwrap();
    let cookie = format!(
        "{}; __Host-auth-oidc-delete-browser={}; __Host-auth-oidc-delete-state={}; __Host-auth-oidc-delete-nonce={}; __Host-auth-oidc-delete-pkce={}",
        f.session_cookie(),
        browser.expose(),
        start.state.expose(),
        start.proof.nonce().expose(),
        start.proof.pkce_verifier().expose()
    );
    let input = json!({"confirmation":"delete my account","state":start.state.expose(),"code":"owned-code","issuer":"https://issuer.example"});
    assert_eq!(
        f.post("finish", input, &cookie).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(f.exists().await);
    assert_eq!(f.pending().await, 1);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    // Positive control proves the exact pending row is still a sign-in context.
    let context = f
        .transactions
        .consume(
            &intent,
            &start.state,
            start.proof,
            OAuthCallback {
                redirect: f.policy.configuration().redirect(),
                issuer: Some(f.policy.configuration().issuer()),
            },
        )
        .await
        .unwrap();
    assert!(matches!(context.purpose(), OAuthPurpose::SignIn));
}

#[sqlx::test]
async fn cancellation_clears_local_proof_after_session_expiry_without_grant(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    f.auth.logout(&f.session).await.unwrap();
    let response = f.post("cancel", json!({}), &attempt.cookie).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(cleared(&response), 4);
    assert!(f.exists().await);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
}
