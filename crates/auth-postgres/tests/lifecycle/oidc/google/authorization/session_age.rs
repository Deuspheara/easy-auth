use super::super::{session_age::setup::selected, setup::Fixture};
use super::setup::{finish, initiated};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::{Arc, atomic::Ordering};

#[sqlx::test(migrations = "./migrations")]
async fn managed_google_session_age_profile_keeps_original_binding_and_never_mints_missing_or_fresh_claims(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone(), false, OidcJitPolicy::Allow).await;
    let foreign = Fixture::new(pool, true, OidcJitPolicy::Allow).await;
    let profile = Arc::new(selected(&f));
    assert!(matches!(
        GoogleAuthorization::new_session_age(Arc::new(foreign.flow()), profile.clone()),
        Err(Error::InvalidInput)
    ));
    assert_eq!(f.provider.document_gets.load(Ordering::SeqCst), 0);
    let service = GoogleAuthorization::new_session_age(Arc::new(f.flow()), profile).unwrap();
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "owned-google-postgres",
        purpose: OAuthPurpose::SignIn,
    };
    let started = service.begin(&intent).await.unwrap();
    let url = url::Url::parse(started.authorization_url.expose()).unwrap();
    let claims: Vec<_> = url
        .query_pairs()
        .filter(|(name, _)| name == "claims")
        .collect();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&claims[0].1).unwrap(),
        json!({"id_token":{"auth_time":{"essential":true}}})
    );
    service
        .cancel(
            &intent,
            &started.transaction.state,
            &started.transaction.proof,
        )
        .await
        .unwrap();
    let missing = initiated(&f, &service, json!({})).await;
    assert!(matches!(
        finish(&f, &service, &missing, None).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(
        f.provider.signed.load(Ordering::SeqCst),
        1,
        "real signed missing-capability response required"
    );
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let old = now - 3600;
    let a = initiated(&f, &service, json!({"auth_time":old})).await;
    let completion = finish(&f, &service, &a, None).await.unwrap();
    let GoogleAuthorizationCompletion::Verified(identity) = completion else {
        panic!("actual signed profile control");
    };
    assert_eq!(identity.authenticated_at(), Some(old as u64));
    assert!(identity.expires_us() <= a.cap);
    assert_eq!(
        f.facts().await,
        (0, 0, 0, 0, 0),
        "selected-profile verification creates no local authority"
    );
    let (owner, session) = OidcSignIn::new(f.store.clone())
        .finish(f.policy.map(*identity).unwrap())
        .await
        .unwrap();
    assert_eq!(
        owner.authentication_policy,
        AuthenticationPolicy::ProviderRequired
    );
    assert!(
        matches!(
            f.store
                .revoke_all_sessions(f.realm(), session.verifier())
                .await,
            Err(Error::Unauthorized)
        ),
        "new session cannot promote old signed authentication"
    );
    assert_eq!(
        f.store
            .authenticate(f.realm(), session.verifier())
            .await
            .unwrap(),
        owner
    );
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 2);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 2);
}
