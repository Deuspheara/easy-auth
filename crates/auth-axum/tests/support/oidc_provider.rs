use async_trait::async_trait;
use auth_core::*;
use josekit::{
    jwk::KeyPair,
    jws::{self, ES256, JwsHeader, JwsSigner},
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

// Trusted fake network boundary only. Identity proof is an actual ES256 signature
// verified by core against the served JWK; no public proof constructor is added.
pub(crate) struct Provider {
    redirect: &'static str,
    public: Value,
    signer: Box<dyn JwsSigner>,
    body: Mutex<Vec<u8>>,
    challenge: Mutex<Option<String>>,
    pub posts: AtomicUsize,
    pub unavailable: AtomicBool,
    pub documents_unavailable: AtomicBool,
}
impl Provider {
    pub fn new(redirect: &'static str) -> Self {
        let key = ES256.generate_key_pair().unwrap();
        let mut public = key.to_jwk_public_key();
        public.set_key_id("owned");
        public.set_algorithm("ES256");
        public.set_key_use("sig");
        Self {
            redirect,
            public: serde_json::to_value(public).unwrap(),
            signer: Box::new(ES256.signer_from_der(key.to_der_private_key()).unwrap()),
            body: Mutex::new(Vec::new()),
            challenge: Mutex::new(None),
            posts: AtomicUsize::new(0),
            unavailable: AtomicBool::new(false),
            documents_unavailable: AtomicBool::new(false),
        }
    }
    pub fn token(&self, claims: Value) -> String {
        let mut header = JwsHeader::new();
        header.set_key_id("owned");
        header.set_token_type("JWT");
        jws::serialize_compact(
            &serde_json::to_vec(&claims).unwrap(),
            &header,
            self.signer.as_ref(),
        )
        .unwrap()
    }
    pub fn prepare(&self, claims: Value, challenge: String) {
        *self.body.lock().unwrap() =
            serde_json::to_vec(&json!({"id_token":self.token(claims),"access_token":"unused-owned-test-token","token_type":"Bearer"})).unwrap();
        *self.challenge.lock().unwrap() = Some(challenge);
    }
}
#[async_trait]
impl OidcHttp for Provider {
    async fn resolve(&self, _: &str, port: u16) -> Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::from(([8, 8, 8, 8], port))])
    }
    async fn get(&self, target: &OidcTarget) -> Result<OidcHttpResponse> {
        if self.documents_unavailable.load(Ordering::SeqCst) {
            return Err(Error::Unavailable);
        }
        let value = if target.url().path().ends_with("openid-configuration") {
            json!({"issuer":"https://issuer.example", "authorization_endpoint":"https://issuer.example/authorize", "token_endpoint":"https://issuer.example/token", "jwks_uri":"https://issuer.example/keys", "authorization_response_iss_parameter_supported":true,"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"]})
        } else {
            json!({"keys":[self.public]})
        };
        Ok(OidcHttpResponse {
            status: 200,
            content_type: Some("application/json".into()),
            content_encoding: None,
            body: serde_json::to_vec(&value).unwrap(),
            cache_seconds: 300,
        })
    }
}
#[async_trait]
impl OidcTokenHttp for Provider {
    async fn post(&self, _: &OidcTarget, request: &OidcTokenRequest) -> Result<OidcTokenResponse> {
        self.posts.fetch_add(1, Ordering::SeqCst);
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(Error::Unavailable);
        }
        let form: std::collections::HashMap<_, _> =
            url::form_urlencoded::parse(request.form().as_bytes())
                .into_owned()
                .collect();
        let proof = OAuthBrowserProof::parse(
            Secret::generate().unwrap().expose().into(),
            form["code_verifier"].clone(),
        )
        .unwrap();
        assert!(
            Some(proof.code_challenge()) == *self.challenge.lock().unwrap(),
            "test infrastructure: token POST must carry original PKCE"
        );
        assert!(request.authorization().is_none());
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["redirect_uri"], self.redirect);
        OidcTokenResponse::new(
            200,
            Some("application/json".into()),
            None,
            self.body.lock().unwrap().clone(),
        )
    }
}
