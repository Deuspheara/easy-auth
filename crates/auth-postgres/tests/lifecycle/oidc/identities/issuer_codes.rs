use super::setup::Fixture;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn issuer_preserves_actual_oidc_authentication_and_rechecks_current_source_at_redemption(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let now = f.now_seconds().await;
    // Reuse the unchanged ordinary signed provider fixture and identity commit.
    let (user, current) = f
        .sign_in
        .finish(f.mapped("subject", json!({"auth_time":now})).await)
        .await
        .unwrap();
    let client = f
        .store
        .configure_issuer_client(
            &IssuerClientRegistration::public(
                f.realm(),
                Uuid::new_v4(),
                &["https://app.example/cb"],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let service = IssuerAuthorization::new(
        IssuerAuthority::new(f.realm(), "https://outbound.example").unwrap(),
        f.store.clone(),
    );
    let browser = Secret::generate().unwrap();
    let pkce = IssuerPkceVerifier::parse(Secret::generate().unwrap().expose().to_owned()).unwrap();
    let input = IssuerAuthorizationInput {
        client: client.client(),
        response_type: "code",
        redirect_uri: "https://app.example/cb",
        scope: "openid",
        state: "state",
        nonce: "nonce",
        code_challenge: &pkce.challenge(),
        code_challenge_method: "S256",
    };
    let pending = service.prepare(&current, &browser, &input).await.unwrap();
    let response = service
        .approve(
            &current,
            &browser,
            pending.handle(),
            pending.authorization(),
        )
        .await
        .unwrap();
    let url = url::Url::parse(response.url()).unwrap();
    let code = Secret::parse(
        url.query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned(),
    )
    .unwrap();
    let grant = service
        .redeem(
            &IssuerClientAuthentication::public(client.client()).unwrap(),
            &code,
            "https://app.example/cb",
            &pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(grant.owner(), user.id);
    assert_eq!(grant.authentication_method(), "oidc");
    assert_eq!(grant.authenticated_at_us(), now * 1_000_000);
    let second = service.prepare(&current, &browser, &input).await.unwrap();
    let response = service
        .approve(&current, &browser, second.handle(), second.authorization())
        .await
        .unwrap();
    let url = url::Url::parse(response.url()).unwrap();
    let code = Secret::parse(
        url.query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned(),
    )
    .unwrap();
    let undecided = service.prepare(&current, &browser, &input).await.unwrap();
    let config = f.policy.configuration();
    f.store
        .disable_oauth_connection(f.realm(), config.connection(), config.client())
        .await
        .unwrap();
    assert!(matches!(
        service.prepare(&current, &browser, &input).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        service
            .approve(
                &current,
                &browser,
                undecided.handle(),
                undecided.authorization()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        service
            .redeem(
                &IssuerClientAuthentication::public(client.client()).unwrap(),
                &code,
                "https://app.example/cb",
                &pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
}
