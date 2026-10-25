use super::{google_setup::GoogleFixture, setup::*};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn last_provider_and_the_current_authenticating_identity_cannot_be_unlinked(pool: PgPool) {
    let f = GoogleFixture::new(pool).await;
    let (owner, current) = f.login("first").await;
    let first = f.identity("first").await;
    assert!(matches!(
        f.linking.unlink(f.realm(), &current, first).await,
        Err(Error::Unauthorized)
    ));
    let second = f.linked(&owner, &current, "second").await;
    // Even with two rows, use an actual fresh retained method instead of counting
    // inventory or treating a possibly disabled alternative as authentication.
    assert!(matches!(
        f.linking.unlink(f.realm(), &current, first).await,
        Err(Error::Unauthorized)
    ));
    f.linking
        .unlink(f.realm(), &current, second.id)
        .await
        .unwrap();
    assert_eq!(
        f.store
            .authenticate(f.realm(), current.verifier())
            .await
            .unwrap(),
        owner
    );
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
    let identities: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1")
            .bind(f.realm())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(identities, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn reciprocal_unlinks_preserve_one_actual_source_and_deny_the_other_after_its_wait(
    pool: PgPool,
) {
    let f = GoogleFixture::new(pool).await;
    let (owner, first_session) = f.login("first").await;
    let first = f.identity("first").await;
    let second = f.linked(&owner, &first_session, "second").await;
    let (returned, second_session) = f.login("second").await;
    assert_eq!(returned, owner);
    let (a, b) = tokio::join!(
        f.linking.unlink(f.realm(), &second_session, first),
        f.linking.unlink(f.realm(), &first_session, second.id)
    );
    assert!(matches!(
        (a, b),
        (Ok(()), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(()))
    ));
    let first_live = f
        .store
        .authenticate(f.realm(), first_session.verifier())
        .await;
    let second_live = f
        .store
        .authenticate(f.realm(), second_session.verifier())
        .await;
    assert!(matches!(
        (first_live, second_live),
        (Ok(_), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(_))
    ));
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1 AND revoked_at IS NULL)").bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(counts, (1, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn genuinely_fresh_linked_provider_session_is_not_a_local_password_mutation_shortcut(
    pool: PgPool,
) {
    let f = GoogleFixture::new(pool).await;
    let (owner, local) = f.local("owner@example.test").await;
    f.linked(&owner, &local, "first").await;
    let (returned, provider_session) = f.login("first").await;
    assert_eq!(returned, owner);
    // This positive second link establishes actual fresh current-source authority;
    // a rejection below therefore cannot be attributed to missing/old auth_time.
    let second = f.linked(&owner, &provider_session, "second").await;
    let service = PasswordService::new("owned known compromised password").unwrap();
    let hash = service
        .enroll(Password::parse("owned strong fresh local control password".to_owned()).unwrap())
        .await
        .unwrap();
    let replacement = Secret::generate().unwrap();
    assert!(matches!(
        f.store
            .enroll_password(
                f.realm(),
                provider_session.verifier(),
                &hash,
                replacement.verifier()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.store
            .authenticate(f.realm(), local.verifier())
            .await
            .unwrap(),
        owner
    );
    f.linking
        .unlink(f.realm(), &local, second.id)
        .await
        .unwrap();
}
