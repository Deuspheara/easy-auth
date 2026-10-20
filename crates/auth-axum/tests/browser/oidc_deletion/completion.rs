use super::setup::*;
use auth_core::Error;
use axum::http::{StatusCode, header};
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test]
async fn fresh_signed_exact_subject_deletes_and_clears_without_issuing_session(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    let response = f
        .post("finish", attempt.callback.clone(), &attempt.cookie)
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(cleared(&response) >= 9);
    for value in response.headers().get_all(header::SET_COOKIE) {
        assert!(
            value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .ends_with('=')
        );
    }
    assert!(!f.exists().await);
    assert_eq!(f.pending().await, 0);
    let counts: (i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_oidc_identities),(SELECT count(*) FROM auth_oidc_deleted_subjects),(SELECT count(*) FROM auth_audit WHERE kind='account_deleted')").fetch_one(&f.pool).await.unwrap();
    assert_eq!(counts, (0, 0, 1, 1));
    assert!(matches!(
        f.auth.authenticate(&f.session).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.post("finish", attempt.callback, &attempt.cookie)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
}

#[sqlx::test]
async fn final_confirmation_is_required_before_consumption(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    let mut input = attempt.callback.clone();
    input["confirmation"] = json!("yes");
    let response = f.post("finish", input, &attempt.cookie).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(cleared(&response), 0);
    assert_eq!(f.pending().await, 1);
    assert!(f.exists().await);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.post("finish", attempt.callback, &attempt.cookie)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
}

#[sqlx::test]
async fn cancellation_is_denial_only_and_cannot_delete(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    assert_eq!(
        f.post(
            "start",
            json!({"confirmation":"delete my account"}),
            &attempt.cookie
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = f.post("cancel", json!({}), &attempt.cookie).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(cleared(&response), 4);
    assert_eq!(f.pending().await, 0);
    assert!(f.exists().await);
    assert!(f.auth.authenticate(&f.session).await.is_ok());
    assert_eq!(
        f.post("finish", attempt.callback, &attempt.cookie)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
}

#[sqlx::test]
async fn logout_clears_opt_in_proof_and_invalidates_it(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    let response = f.app.clone();
    use tower::ServiceExt;
    let response = response
        .oneshot(crate::support::post(
            "/v1/logout",
            "{}",
            Some(&attempt.cookie),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(cleared(&response), 5); // Session plus four deletion proof cookies.
    assert_eq!(
        f.post("finish", attempt.callback, &attempt.cookie)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(f.exists().await);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
}
