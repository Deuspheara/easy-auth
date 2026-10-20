use super::super::setup::Fixture;
use super::setup::*;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test(migrations = "./migrations")]
async fn google_selected_session_age_missing_malformed_and_old_claims_preserve_owner_until_fresh_signed_deletion(
    pool: PgPool,
) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let (user, current) = account(&f, "owned").await;
    for (attributes, unavailable) in [
        (json!({}), true),
        (json!({"auth_time":null}), false),
        (json!({"auth_time":"recent"}), false),
    ] {
        let result = proof(&f, &user, &current, "owned", attributes).await;
        assert!(matches!(
            (unavailable, result),
            (true, Err(Error::Unavailable)) | (false, Err(Error::Unauthorized))
        ));
        assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
        assert_eq!(
            f.store
                .authenticate(f.realm(), current.verifier())
                .await
                .unwrap(),
            user
        );
    }
    assert_eq!(
        f.provider.signed.load(Ordering::SeqCst),
        4,
        "actual signed profile failures, not fake storage denial"
    );
    let old = now(&f).await - i64::try_from(MAX_OIDC_DELETION_AUTH_AGE_SECONDS).unwrap() - 1;
    let identity = proof(&f, &user, &current, "owned", json!({"auth_time":old}))
        .await
        .unwrap();
    assert_eq!(identity.authenticated_at(), Some(old as u64));
    assert!(matches!(
        remove(&f, identity).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    let identity = proof(
        &f,
        &user,
        &current,
        "owned",
        json!({"auth_time":now(&f).await}),
    )
    .await
    .unwrap();
    remove(&f, identity).await.unwrap();
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
    assert!(matches!(
        f.store.authenticate(f.realm(), current.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 6);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 6);
    let resurrect = f.mapped("owned", json!({})).await;
    assert!(
        matches!(f.sign_in(resurrect).await, Err(Error::Unauthorized)),
        "Google sign-in cannot bypass existing deleted-subject cooldown"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn google_selected_session_age_retains_exact_owner_session_subject_and_deletion_purpose(
    pool: PgPool,
) {
    let f = Fixture::new(pool, false, OidcJitPolicy::Allow).await;
    let (first, current) = account(&f, "first").await;
    let (second, other) = account(&f, "second").await;
    let before = f.provider.posts.load(Ordering::SeqCst);
    assert!(matches!(
        proof(
            &f,
            &first,
            &other,
            "first",
            json!({"auth_time":now(&f).await})
        )
        .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.provider.posts.load(Ordering::SeqCst),
        before,
        "wrong initiating session rejected before provider I/O"
    );
    let wrong = proof(
        &f,
        &first,
        &current,
        "second",
        json!({"auth_time":now(&f).await}),
    )
    .await
    .unwrap();
    assert!(matches!(remove(&f, wrong).await, Err(Error::Unauthorized)));
    let a = f
        .prepare("first", json!({"auth_time":now(&f).await}), None)
        .await;
    let signin = selected(&f)
        .exchange(f.consume(&a).await.unwrap(), a.authorization_code())
        .await
        .unwrap();
    assert!(
        matches!(remove(&f, signin).await, Err(Error::Unauthorized)),
        "signed sign-in cannot authorize deletion"
    );
    assert_eq!(f.facts().await, (2, 2, 2, 2, 0));
    let identity = proof(
        &f,
        &first,
        &current,
        "first",
        json!({"auth_time":now(&f).await}),
    )
    .await
    .unwrap();
    remove(&f, identity).await.unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 3, 0));
    assert_eq!(
        f.store
            .authenticate(f.realm(), other.verifier())
            .await
            .unwrap(),
        second
    );
    assert!(matches!(
        f.store.authenticate(f.realm(), current.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 5);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 5);
}
