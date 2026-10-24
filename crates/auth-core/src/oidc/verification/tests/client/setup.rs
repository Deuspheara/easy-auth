use super::super::setup::{Fixture, TokenHttp};
use crate::*;
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub(super) struct ClientFixture {
    pub provider: Fixture,
    pub post: Arc<TokenHttp>,
    pub client: OidcClient,
    pub id: Uuid,
}
impl ClientFixture {
    pub fn new() -> Self {
        let provider = Fixture::new(OidcSigningAlgorithm::RS256, &[]);
        provider.http.metadata.lock().unwrap()["token_endpoint_auth_methods_supported"] =
            json!(["none", "client_secret_basic"]);
        let post = TokenHttp::new();
        let id = Uuid::new_v4();
        let client = Self::service(&provider, post.clone(), id);
        Self {
            provider,
            post,
            client,
            id,
        }
    }
    pub fn service(provider: &Fixture, post: Arc<TokenHttp>, id: Uuid) -> OidcClient {
        let configuration = OidcClientConfiguration::web(
            "https://issuer.example",
            id,
            "https://rp.example/callback?tenant=one",
            OidcClientAuthentication::Public,
        )
        .unwrap();
        OidcClient::new(configuration, provider.http.clone(), post).unwrap()
    }
    pub fn success(&self, pending: &OidcClientAuthorization) {
        let parameters = parameters(pending);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = json!({"iss":"https://issuer.example", "aud":self.id.to_string(),
            "sub":"pairwise-subject", "iat":now, "exp":now + 60, "auth_time":now,
            "nonce":parameters["nonce"]});
        // Reuse the unchanged maintained normal signer; no new crypto fixture.
        let token = self.provider.key.raw(&serde_json::to_vec(&claims).unwrap());
        *self.post.body.lock().unwrap() = serde_json::to_vec(&json!({
            "id_token":token, "access_token":Secret::generate().unwrap().expose(),
            "token_type":"Bearer", "expires_in":60, "scope":"openid"
        }))
        .unwrap();
    }
}
pub(super) fn parameters(pending: &OidcClientAuthorization) -> BTreeMap<String, String> {
    url::Url::parse(pending.authorization_url())
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}
pub(super) fn callback(pending: &OidcClientAuthorization) -> url::Url {
    let mut callback = url::Url::parse("https://rp.example/callback?tenant=one").unwrap();
    callback
        .query_pairs_mut()
        .append_pair("state", &parameters(pending)["state"])
        .append_pair("iss", "https://issuer.example")
        .append_pair("code", Secret::generate().unwrap().expose());
    callback
}
