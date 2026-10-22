use super::setup::Fixture;
use auth_core::{Error, Repository, SamlBrowserProof, Secret};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn sign_in_and_deletion_cannot_consume_or_cancel_each_others_purpose(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let deletion = f.requests.start(&f.current).await.unwrap();
    assert!(matches!(
        f.source
            .flow
            .prepare_response(
                deletion.request_id(),
                deletion.relay_state(),
                deletion.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.source
            .flow
            .cancel(
                deletion.request_id(),
                deletion.relay_state(),
                deletion.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let signin = f.source.flow.start().await.unwrap();
    assert!(matches!(
        f.requests
            .prepare_response(
                &f.current,
                signin.request_id(),
                signin.relay_state(),
                signin.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.requests
            .cancel(
                &f.current,
                signin.request_id(),
                signin.relay_state(),
                signin.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 2);
    f.requests
        .cancel(
            &f.current,
            deletion.request_id(),
            deletion.relay_state(),
            deletion.browser_proof(),
        )
        .await
        .unwrap();
    f.source
        .flow
        .prepare_response(
            signin.request_id(),
            signin.relay_state(),
            signin.browser_proof(),
        )
        .await
        .unwrap();
    assert_eq!(f.pending().await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn another_owner_session_or_browser_cannot_select_the_initiating_request(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let same_owner = f.another_session("normal").await;
    let other = f.another_session("other").await;
    let start = f.requests.start(&f.current).await.unwrap();
    for current in [&same_owner, &other] {
        assert!(matches!(
            f.requests
                .prepare_response(
                    current,
                    start.request_id(),
                    start.relay_state(),
                    start.browser_proof()
                )
                .await,
            Err(Error::Unauthorized)
        ));
    }
    let wrong = Secret::generate().unwrap();
    let browser = SamlBrowserProof::parse(wrong.expose().to_owned()).unwrap();
    assert!(matches!(
        f.requests
            .prepare_response(
                &f.current,
                start.request_id(),
                &wrong,
                start.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.requests
            .prepare_response(
                &f.current,
                start.request_id(),
                start.relay_state(),
                &browser
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 1);
    let prepared = f
        .requests
        .prepare_response(
            &f.current,
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    assert_eq!(prepared.binding().user, f.user.id);
}

#[sqlx::test(migrations = "./migrations")]
async fn revocation_policy_change_and_disable_deny_preparation_without_weaker_fallback(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let start = f.requests.start(&f.current).await.unwrap();
    f.source
        .store
        .revoke(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
    assert!(matches!(
        f.requests
            .prepare_response(
                &f.current,
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.requests.start(&f.current).await,
        Err(Error::Unauthorized)
    ));
    let fresh = f.another_session("normal").await;
    sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2")
        .bind(f.user.realm_id).bind(f.user.id).execute(&f.source.pool).await.unwrap();
    assert!(matches!(
        f.requests.start(&fresh).await,
        Err(Error::Unauthorized)
    ));
    sqlx::query("UPDATE auth_users SET authentication_policy='provider_required' WHERE realm_id=$1 AND id=$2")
        .bind(f.user.realm_id).bind(f.user.id).execute(&f.source.pool).await.unwrap();
    let current = f.requests.start(&fresh).await.unwrap();
    let r = &f.source.registration;
    f.source
        .store
        .disable_saml_registration(r.realm(), r.connection(), r.client())
        .await
        .unwrap();
    assert!(matches!(
        f.requests
            .prepare_response(
                &fresh,
                current.request_id(),
                current.relay_state(),
                current.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 0);
}
