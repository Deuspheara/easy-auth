pub(super) use super::super::setup::{Fixture, NOW_US, TokenHttp};
pub(super) use crate::*;
use josekit::jwk::KeyPair;
pub(super) use serde_json::json;
pub(super) use std::sync::{Arc, atomic::Ordering};
use uuid::Uuid;

pub(super) fn fixture() -> Fixture {
    let connection = OAuthConnection::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        "https://appleid.apple.com",
        "com.example.auth",
        "https://app.example/apple/callback",
        OAuthMixupDefense::DedicatedRedirect,
    )
    .unwrap();
    Fixture::configured(
        OidcSigningAlgorithm::RS256,
        &[],
        connection,
        &["https://appleid.apple.com"],
        json!({"issuer":"https://appleid.apple.com","authorization_endpoint":"https://appleid.apple.com/auth/authorize",
        "token_endpoint":"https://appleid.apple.com/auth/token","jwks_uri":"https://appleid.apple.com/auth/keys",
        "token_endpoint_auth_methods_supported":["client_secret_post"]}),
    )
}
pub(super) fn client(
    f: &Fixture,
    tokens: Arc<TokenHttp>,
    kind: AppleClientType,
) -> AppleCodeExchange {
    let key = josekit::jws::ES256.generate_key_pair().unwrap();
    let signer = AppleClientSecretSigner::from_pkcs8_pem(
        "TEAM000001",
        f.store.connection.provider_client(),
        "KEY0000001",
        NOW_US as u64 / 1_000_000,
        NOW_US as u64 / 1_000_000 + 1000,
        String::from_utf8(key.to_pem_private_key()).unwrap(),
    )
    .unwrap();
    AppleCodeExchange::new(
        f.store.connection.clone(),
        f.store.clone(),
        f.store.clone(),
        signer,
        kind,
        f.http.clone(),
        tokens,
    )
    .unwrap()
}
pub(super) fn code() -> OidcAuthorizationCode {
    OidcAuthorizationCode::parse("owned-apple-authorization-code".to_owned()).unwrap()
}
