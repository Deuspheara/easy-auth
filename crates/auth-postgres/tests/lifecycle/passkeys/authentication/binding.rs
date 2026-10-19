use super::*;
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn a_source_cannot_evade_admission_by_rotating_browser_bindings(pool: PgPool) {
    let f = SignIn::new(pool.clone()).await;
    for _ in 0..40 {
        let browser = Secret::generate().unwrap();
        f.flow.begin_discoverable(&browser, SOURCE).await.unwrap();
    }
    let browser = Secret::generate().unwrap();
    assert!(matches!(
        f.flow.begin_discoverable(&browser, SOURCE).await,
        Err(Error::RateLimited)
    ));
    assert_eq!(authentication_count(&pool).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn signed_login_atomically_updates_key_issues_owned_session_and_audits(pool: PgPool) {
    let mut f = SignIn::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    let session = f
        .flow
        .finish(&f.enrollment.browser, SOURCE, id, &response)
        .await
        .unwrap();
    let user = f
        .enrollment
        .store
        .authenticate(f.enrollment.realm, session.verifier())
        .await
        .unwrap();
    assert_eq!(user.id, f.owner);
    let (method, fresh): (String, bool) = sqlx::query_as("SELECT authentication_method,authenticated_at>clock_timestamp()-interval '1 minute' FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
        .bind(f.enrollment.realm).bind(session.verifier().as_slice()).fetch_one(&pool).await.unwrap();
    assert_eq!(method, "passkey");
    assert!(fresh);
    let (encoded, used): (Vec<u8>, bool) = sqlx::query_as("SELECT credential,last_used_at IS NOT NULL FROM auth_passkeys WHERE realm_id=$1 AND user_id=$2")
        .bind(f.enrollment.realm).bind(f.owner).fetch_one(&pool).await.unwrap();
    assert!(used);
    let credential: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(credential["cred"]["counter"], 1);
    assert_eq!(authentication_count(&pool).await, 1);
    let fact:(Uuid,Option<Uuid>,bool,i16)=sqlx::query_as("SELECT user_id,actor_session_id,session_id IS NOT NULL,schema_version FROM auth_audit WHERE kind='passkey_authenticated'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(fact, (f.owner, None, true, 1));
    assert!(matches!(
        f.flow
            .finish(&f.enrollment.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkey_authentications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pending, 0);
    let other = Uuid::new_v4();
    f.enrollment.store.ensure_realm(other).await.unwrap();
    assert!(
        f.enrollment
            .store
            .authenticate(other, session.verifier())
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn conditional_proof_is_bound_to_browser_realm_and_owned_handle(pool: PgPool) {
    let mut f = SignIn::new(pool.clone()).await;
    let pending = f
        .flow
        .begin_discoverable(&f.enrollment.browser, SOURCE)
        .await
        .unwrap();
    let mut options = pending.options;
    assert!(options.public_key.allow_credentials.is_empty());
    // Software signer lacks discovery. Only its input receives a known key; persisted
    // state remains discoverable. Native browser discovery is a separate required test.
    options.public_key.allow_credentials =
        serde_json::from_value(serde_json::json!([{"id":f.credential_id,"type":"public-key"}]))
            .unwrap();
    let mut response = f
        .token
        .perform_auth(ORIGIN.parse().unwrap(), options.public_key, 120_000)
        .unwrap();
    response.response.user_handle = Some(f.owner.as_bytes().to_vec().into());
    let wrong_browser = Secret::generate().unwrap();
    assert!(matches!(
        f.flow
            .finish(&wrong_browser, SOURCE, pending.transaction, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    let other = Uuid::new_v4();
    f.enrollment.store.ensure_realm(other).await.unwrap();
    let foreign = PasskeySignIn::new(
        other,
        f.enrollment.service.clone(),
        f.enrollment.store.clone(),
    );
    assert!(matches!(
        foreign
            .finish(
                &f.enrollment.browser,
                SOURCE,
                pending.transaction,
                &response
            )
            .await,
        Err(Error::Unauthorized)
    ));
    response.response.user_handle = Some(Uuid::new_v4().as_bytes().to_vec().into());
    assert!(matches!(
        f.flow
            .finish(
                &f.enrollment.browser,
                SOURCE,
                pending.transaction,
                &response
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(authentication_count(&pool).await, 0);
    response.response.user_handle = Some(f.owner.as_bytes().to_vec().into());
    assert!(
        f.flow
            .finish(
                &f.enrollment.browser,
                SOURCE,
                pending.transaction,
                &response
            )
            .await
            .is_ok()
    );
    assert_eq!(authentication_count(&pool).await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn pending_and_failed_attempts_are_bounded_and_expired_state_is_reclaimed(pool: PgPool) {
    let mut f = SignIn::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    for _ in 0..2 {
        f.flow
            .begin_discoverable(&f.enrollment.browser, SOURCE)
            .await
            .unwrap();
    }
    assert!(matches!(
        f.flow
            .begin_discoverable(&f.enrollment.browser, SOURCE)
            .await,
        Err(Error::RateLimited)
    ));
    sqlx::query(
        "UPDATE auth_passkey_authentications SET expires_at=clock_timestamp()-interval '1 second'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        f.flow
            .finish(&f.enrollment.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    f.flow
        .begin_discoverable(&f.enrollment.browser, SOURCE)
        .await
        .unwrap();
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkey_authentications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1);
    let mut malformed = response;
    malformed.raw_id = Vec::<u8>::new().into();
    // One finish already spent budget. Invalid IDs must spend the other 19, too.
    for _ in 0..19 {
        assert!(matches!(
            f.flow
                .finish(&f.enrollment.browser, SOURCE, Uuid::new_v4(), &malformed)
                .await,
            Err(Error::Unauthorized)
        ));
    }
    assert!(matches!(
        f.flow
            .finish(&f.enrollment.browser, SOURCE, id, &malformed)
            .await,
        Err(Error::RateLimited)
    ));
    assert_eq!(authentication_count(&pool).await, 0);
}
