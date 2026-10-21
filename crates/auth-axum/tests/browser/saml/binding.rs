use super::setup::{Fixture, ORIGIN};
use auth_core::Secret;
use sqlx::PgPool;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn private_browser_proof_origin_and_existing_session_are_required_before_consumption(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    for cookie in [None, Some("__Host-auth-saml-browser=invalid")] {
        assert_eq!(
            f.deliver("/v1/saml/sign-in/finish", &attempt, cookie, Some(ORIGIN))
                .await
                .status(),
            401
        );
    }
    for origin in [None, Some("https://idp.example")] {
        assert_eq!(
            f.deliver(
                "/v1/saml/sign-in/finish",
                &attempt,
                Some(&attempt.cookie),
                origin
            )
            .await
            .status(),
            403
        );
    }
    let session = format!(
        "{}; __Host-auth-session={}",
        attempt.cookie,
        Secret::generate().unwrap().expose()
    );
    assert_eq!(
        f.deliver(
            "/v1/saml/sign-in/finish",
            &attempt,
            Some(&session),
            Some(ORIGIN)
        )
        .await
        .status(),
        401
    );
    let duplicate = format!("{}; {}", attempt.cookie, attempt.cookie);
    assert_eq!(
        f.deliver(
            "/v1/saml/sign-in/finish",
            &attempt,
            Some(&duplicate),
            Some(ORIGIN)
        )
        .await
        .status(),
        401
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    assert_eq!(
        f.deliver(
            "/v1/saml/sign-in/finish",
            &attempt,
            Some(&attempt.cookie),
            Some(ORIGIN)
        )
        .await
        .status(),
        204
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn another_browser_cannot_complete_the_original_attempt(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let b = f.start().await;
    assert_eq!(
        f.deliver("/v1/saml/sign-in/finish", &a, Some(&b.cookie), Some(ORIGIN))
            .await
            .status(),
        401
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 2));
    assert_eq!(
        f.deliver("/v1/saml/sign-in/finish", &a, Some(&a.cookie), Some(ORIGIN))
            .await
            .status(),
        204
    );
    assert_eq!(
        f.deliver("/v1/saml/sign-in/finish", &b, Some(&b.cookie), Some(ORIGIN))
            .await
            .status(),
        204
    );
    assert_eq!(f.facts().await, (1, 1, 2, 4, 0));
}
