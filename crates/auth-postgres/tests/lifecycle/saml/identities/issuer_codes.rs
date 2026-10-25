use super::setup::{allow_jit, fixture, verify};
use auth_core::*;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn issuer_consent_and_redemption_require_the_original_current_saml_source(pool: PgPool) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    // Reuse the unchanged ordinary IdP producer and production verifier/commit.
    let (user, current) = SamlSignIn::new(f.store.clone())
        .finish(policy.map(verify(&f, "normal").await).unwrap())
        .await
        .unwrap();
    let client = f
        .store
        .configure_issuer_client(
            &IssuerClientRegistration::public(
                user.realm_id,
                Uuid::new_v4(),
                &["https://app.example/cb"],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let service = IssuerAuthorization::new(
        IssuerAuthority::new(user.realm_id, "https://outbound.example").unwrap(),
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
    assert_eq!(grant.authentication_method(), "saml");
    let signed_authentication: i64 = sqlx::query_scalar("SELECT (extract(epoch FROM authenticated_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
        .bind(user.realm_id).bind(current.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(grant.authenticated_at_us(), signed_authentication);
    let second = service.prepare(&current, &browser, &input).await.unwrap();
    let approved = service
        .approve(&current, &browser, second.handle(), second.authorization())
        .await
        .unwrap();
    let url = url::Url::parse(approved.url()).unwrap();
    let second_code = Secret::parse(
        url.query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned(),
    )
    .unwrap();
    let undecided = service.prepare(&current, &browser, &input).await.unwrap();
    f.store
        .disable_saml_registration(
            user.realm_id,
            f.registration.connection(),
            f.registration.client(),
        )
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
                &second_code,
                "https://app.example/cb",
                &pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
}
