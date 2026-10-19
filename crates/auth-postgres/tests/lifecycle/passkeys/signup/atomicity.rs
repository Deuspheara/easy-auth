use super::*;
use auth_core::{AuthenticationPolicy, Error, PasskeySignIn};

#[sqlx::test(migrations = "./migrations")]
async fn registration_stays_pending_until_assertion_and_new_account_can_authenticate_again(
    pool: PgPool,
) {
    let mut f = Signup::new(pool).await;
    let (id, response) = f.registration().await;
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
    let pending = f
        .flow
        .finish_registration(&f.browser, SOURCE, id, &response)
        .await
        .unwrap();
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
    let response = f
        .token
        .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
        .unwrap();
    let session = f
        .flow
        .finish(&f.browser, SOURCE, id, &response)
        .await
        .unwrap();
    let user = f
        .store
        .authenticate(f.realm, session.verifier())
        .await
        .unwrap();
    assert_eq!(user.email, None);
    assert_eq!(user.display_name.as_deref(), Some("Example person"));
    assert_eq!(
        user.authentication_policy,
        AuthenticationPolicy::PasskeyRequired
    );
    assert_eq!(f.durable_counts().await, (1, 1, 1, 1));
    assert!(matches!(
        f.flow.finish(&f.browser, SOURCE, id, &response).await,
        Err(Error::Unauthorized)
    ));
    let method: String =
        sqlx::query_scalar("SELECT authentication_method FROM auth_sessions WHERE token_hash=$1")
            .bind(session.verifier().as_slice())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(method, "passkey");
    let sign_in = PasskeySignIn::new(f.realm, f.service.clone(), f.store.clone());
    let other_browser = Secret::generate().unwrap();
    let pending = sign_in
        .begin_account(user.id, &other_browser, SOURCE)
        .await
        .unwrap();
    let response = f
        .token
        .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
        .unwrap();
    let next = sign_in
        .finish(&other_browser, SOURCE, pending.transaction, &response)
        .await
        .unwrap();
    assert_eq!(
        f.store
            .authenticate(f.realm, next.verifier())
            .await
            .unwrap()
            .id,
        user.id
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn session_or_audit_failure_rolls_back_identity_key_and_consumption(pool: PgPool) {
    let mut f = Signup::new(pool).await;
    let (id, response) = f.assertion().await;
    for (table, condition) in [
        ("auth_sessions", "authentication_method<>'passkey'"),
        ("auth_audit", "kind<>'passkey_signed_up'"),
    ] {
        sqlx::query(&format!(
            "ALTER TABLE {table} ADD CONSTRAINT injected_signup_failure CHECK ({condition})"
        ))
        .execute(&f.pool)
        .await
        .unwrap();
        assert!(matches!(
            f.flow.finish(&f.browser, SOURCE, id, &response).await,
            Err(Error::Unavailable)
        ));
        assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM auth_passkey_signups WHERE id=$1 AND stage='assertion'",
        )
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(pending, 1);
        sqlx::query(&format!(
            "ALTER TABLE {table} DROP CONSTRAINT injected_signup_failure"
        ))
        .execute(&f.pool)
        .await
        .unwrap();
    }
    assert!(
        f.flow
            .finish(&f.browser, SOURCE, id, &response)
            .await
            .is_ok()
    );
    assert_eq!(f.durable_counts().await, (1, 1, 1, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_registration_and_assertion_each_have_one_winner(pool: PgPool) {
    let mut f = Signup::new(pool).await;
    let (id, response) = f.registration().await;
    let (a, b) = tokio::join!(
        f.flow
            .finish_registration(&f.browser, SOURCE, id, &response),
        f.flow
            .finish_registration(&f.browser, SOURCE, id, &response)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let pending = a.ok().or(b.ok()).unwrap();
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
    let response = f
        .token
        .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
        .unwrap();
    let (a, b) = tokio::join!(
        f.flow.finish(&f.browser, SOURCE, id, &response),
        f.flow.finish(&f.browser, SOURCE, id, &response)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(f.durable_counts().await, (1, 1, 1, 1));
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_passkey_signups WHERE realm_id=$1")
            .bind(f.realm)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(pending, 0);
}
