use async_trait::async_trait;
use auth_core::*;
use josekit::{
    jwk::KeyPair,
    jws::{self, ES256, JwsHeader, JwsSigner, JwsVerifier, RS256},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::sync::Notify;

pub(super) const ISSUER: &str = "https://appleid.apple.com";
pub(super) const CLIENT: &str = "com.example.owned-apple";
struct Grant {
    claims: Value,
    redirect: Option<String>,
}
pub(super) struct Provider {
    signer: Box<dyn JwsSigner>,
    credential_verifier: Box<dyn JwsVerifier>,
    public: Value,
    grants: Mutex<HashMap<Verifier, Grant>>,
    pub posts: AtomicUsize,
    pub signed: AtomicUsize,
    pub hold: AtomicBool,
    pub entered: Notify,
    pub release: Notify,
}
impl Provider {
    pub fn new(now: u64) -> (Arc<Self>, AppleClientSecretSigner) {
        let key = RS256.generate_key_pair(2048).unwrap();
        let signer = RS256.signer_from_der(key.to_der_private_key()).unwrap();
        let mut public = key.to_jwk_public_key();
        public.set_key_id("owned-apple");
        public.set_algorithm("RS256");
        public.set_key_use("sig");
        let credential = ES256.generate_key_pair().unwrap();
        let verifier = ES256
            .verifier_from_pem(credential.to_pem_public_key())
            .unwrap();
        let secrets = AppleClientSecretSigner::from_pkcs8_pem(
            "TEAM000001",
            CLIENT,
            "KEY0000001",
            now.saturating_sub(1),
            now + 3600,
            String::from_utf8(credential.to_pem_private_key()).unwrap(),
        )
        .unwrap();
        (
            Arc::new(Self {
                signer: Box::new(signer),
                credential_verifier: Box::new(verifier),
                public: serde_json::to_value(public).unwrap(),
                grants: Mutex::new(HashMap::new()),
                posts: AtomicUsize::new(0),
                signed: AtomicUsize::new(0),
                hold: AtomicBool::new(false),
                entered: Notify::new(),
                release: Notify::new(),
            }),
            secrets,
        )
    }
    pub fn issue(&self, code: &Secret, claims: Value, redirect: Option<&str>) {
        assert!(
            self.grants
                .lock()
                .unwrap()
                .insert(
                    code.verifier(),
                    Grant {
                        claims,
                        redirect: redirect.map(str::to_owned)
                    }
                )
                .is_none()
        );
    }
}
#[async_trait]
impl OidcHttp for Provider {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        assert_eq!(host, "appleid.apple.com");
        assert_eq!(port, 443);
        Ok(vec!["8.8.8.8:443".parse().unwrap()])
    }
    async fn get(&self, target: &OidcTarget) -> Result<OidcHttpResponse> {
        let value = match target.url().as_str() {
            "https://appleid.apple.com/.well-known/openid-configuration" => {
                json!({"issuer":ISSUER,"authorization_endpoint":"https://appleid.apple.com/auth/authorize",
                "token_endpoint":"https://appleid.apple.com/auth/token","jwks_uri":"https://appleid.apple.com/auth/keys","token_endpoint_auth_methods_supported":["client_secret_post"]})
            }
            "https://appleid.apple.com/auth/keys" => json!({"keys":[self.public]}),
            _ => panic!("unexpected owned Apple document request"),
        };
        Ok(OidcHttpResponse {
            status: 200,
            content_type: Some("application/json".to_owned()),
            content_encoding: None,
            body: serde_json::to_vec(&value).unwrap(),
            cache_seconds: 300,
        })
    }
}
#[async_trait]
impl OidcTokenHttp for Provider {
    async fn post(
        &self,
        target: &OidcTarget,
        request: &OidcTokenRequest,
    ) -> Result<OidcTokenResponse> {
        self.posts.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            target.url().as_str(),
            "https://appleid.apple.com/auth/token"
        );
        assert_eq!(target.addresses(), ["8.8.8.8:443".parse().unwrap()]);
        assert!(request.authorization().is_none());
        let fields: Vec<_> = url::form_urlencoded::parse(request.form().as_bytes()).collect();
        let field = |name: &str| {
            let values: Vec<_> = fields.iter().filter(|(key, _)| key == name).collect();
            assert_eq!(values.len(), 1, "one original Apple wire member required");
            values[0].1.as_ref()
        };
        assert!(field("grant_type") == "authorization_code" && field("client_id") == CLIENT);
        let code = Secret::parse(field("code").to_owned()).expect("owned issued code required");
        let grant = self
            .grants
            .lock()
            .unwrap()
            .remove(&code.verifier())
            .expect("one-use issued provider code required, not an auth rejection");
        assert_eq!(fields.len(), if grant.redirect.is_some() { 5 } else { 4 });
        assert!(!fields.iter().any(|(name, _)| name == "code_verifier"));
        if let Some(redirect) = &grant.redirect {
            assert!(field("redirect_uri") == redirect);
        } else {
            assert!(!fields.iter().any(|(name, _)| name == "redirect_uri"));
        }
        let (payload, header) =
            jws::deserialize_compact(field("client_secret"), self.credential_verifier.as_ref())
                .expect("actual registered ES256 credential signature");
        let secret: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(header.key_id(), Some("KEY0000001"));
        assert_eq!(secret["iss"], "TEAM000001");
        assert_eq!(secret["sub"], CLIENT);
        assert_eq!(secret["aud"], ISSUER);
        assert!(secret["exp"].as_u64().unwrap() - secret["iat"].as_u64().unwrap() <= 300);
        if self.hold.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        let mut header = JwsHeader::new();
        header.set_key_id("owned-apple");
        header.set_token_type("JWT");
        let token = jws::serialize_compact(
            &serde_json::to_vec(&grant.claims).unwrap(),
            &header,
            self.signer.as_ref(),
        )
        .unwrap();
        self.signed.fetch_add(1, Ordering::SeqCst);
        OidcTokenResponse::new(200, Some("application/json".to_owned()), None,
            serde_json::to_vec(&json!({"id_token":token,"access_token":"unused-owned-token","token_type":"Bearer","refresh_token":"unused-owned-refresh"})).unwrap())
    }
}
