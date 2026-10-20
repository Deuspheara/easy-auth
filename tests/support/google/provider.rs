use async_trait::async_trait;
use auth_core::*;
use josekit::{
    jwk::KeyPair,
    jws::{self, JwsHeader, JwsSigner, RS256},
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

pub(super) const ISSUER: &str = "https://accounts.google.com";
pub(super) const CLIENT: &str = "owned-google-client.apps.googleusercontent.com";
struct Grant {
    claims: Value,
    redirect: String,
    pkce: Verifier,
}

pub(super) struct Provider {
    signer: Box<dyn JwsSigner>,
    public: Value,
    secret: Secret,
    grants: Mutex<HashMap<Verifier, Grant>>,
    pub posts: AtomicUsize,
    pub signed: AtomicUsize,
    pub unavailable: AtomicBool,
    pub documents_unavailable: AtomicBool,
    pub document_gets: AtomicUsize,
    pub hold: AtomicBool,
    pub entered: Notify,
    pub release: Notify,
}
impl Provider {
    pub fn new() -> Arc<Self> {
        let key = RS256
            .generate_key_pair(2048)
            .expect("test infrastructure: owned RSA signing key");
        let signer = RS256.signer_from_der(key.to_der_private_key()).unwrap();
        let mut public = key.to_jwk_public_key();
        public.set_key_id("owned-google");
        public.set_algorithm("RS256");
        public.set_key_use("sig");
        Arc::new(Self {
            signer: Box::new(signer),
            public: serde_json::to_value(public).unwrap(),
            secret: Secret::generate().unwrap(),
            grants: Mutex::new(HashMap::new()),
            posts: AtomicUsize::new(0),
            signed: AtomicUsize::new(0),
            unavailable: AtomicBool::new(false),
            documents_unavailable: AtomicBool::new(false),
            document_gets: AtomicUsize::new(0),
            hold: AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        })
    }
    pub fn authentication(&self) -> OidcClientAuthentication {
        OidcClientAuthentication::ClientSecretPost(
            OidcClientSecret::parse(self.secret.expose().to_owned()).unwrap(),
        )
    }
    // The browser-facing provider sees only the public authorization request's
    // S256 challenge, nonce and exact redirect, never the private browser proof.
    pub fn issue(&self, code: &Secret, pkce: Verifier, c: &OAuthConnection, claims: Value) {
        self.issue_for_return(code, pkce, c, c.redirect(), claims);
    }
    pub fn issue_for_return(
        &self,
        code: &Secret,
        pkce: Verifier,
        c: &OAuthConnection,
        redirect: &str,
        claims: Value,
    ) {
        assert_eq!(c.provider_client(), CLIENT);
        assert!(c.permits_return(redirect));
        assert!(
            self.grants
                .lock()
                .unwrap()
                .insert(
                    code.verifier(),
                    Grant {
                        claims,
                        redirect: redirect.to_owned(),
                        pkce
                    }
                )
                .is_none()
        );
    }
}
#[async_trait]
impl OidcHttp for Provider {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        assert!(
            matches!(
                host,
                "accounts.google.com" | "oauth2.googleapis.com" | "www.googleapis.com"
            ),
            "unexpected fixture endpoint"
        );
        assert_eq!(port, 443);
        Ok(vec![SocketAddr::from(([8, 8, 8, 8], port))])
    }
    async fn get(&self, target: &OidcTarget) -> Result<OidcHttpResponse> {
        self.document_gets.fetch_add(1, Ordering::SeqCst);
        if self.documents_unavailable.load(Ordering::SeqCst) {
            return Err(Error::Unavailable);
        }
        let value = match target.url().as_str() {
            "https://accounts.google.com/.well-known/openid-configuration" => {
                json!({"issuer":ISSUER,
                "authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth","token_endpoint":"https://oauth2.googleapis.com/token",
                "jwks_uri":"https://www.googleapis.com/oauth2/v3/certs","authorization_response_iss_parameter_supported":true,
                "code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["client_secret_post"]})
            }
            "https://www.googleapis.com/oauth2/v3/certs" => json!({"keys":[self.public]}),
            _ => panic!("unexpected owned provider GET"),
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
    async fn post(
        &self,
        target: &OidcTarget,
        request: &OidcTokenRequest,
    ) -> Result<OidcTokenResponse> {
        self.posts.fetch_add(1, Ordering::SeqCst);
        assert_eq!(target.url().as_str(), "https://oauth2.googleapis.com/token");
        assert_eq!(target.addresses(), ["8.8.8.8:443".parse().unwrap()]);
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(Error::Unavailable);
        }
        let fields: Vec<_> = url::form_urlencoded::parse(request.form().as_bytes()).collect();
        assert_eq!(fields.len(), 6, "exact registered Post wire contract");
        let field = |name: &str| {
            let values: Vec<_> = fields.iter().filter(|(key, _)| key == name).collect();
            assert_eq!(values.len(), 1, "one original wire parameter required");
            values[0].1.as_ref()
        };
        assert!(request.authorization().is_none());
        assert!(field("grant_type") == "authorization_code" && field("client_id") == CLIENT);
        let code =
            Secret::parse(field("code").to_owned()).expect("original owned authorization code");
        let grant = self
            .grants
            .lock()
            .unwrap()
            .remove(&code.verifier())
            .expect("issued one-use provider code required; not an auth rejection");
        assert!(
            field("redirect_uri") == grant.redirect,
            "original exact registered redirect required"
        );
        assert!(
            Secret::parse(field("code_verifier").to_owned())
                .unwrap()
                .verifier()
                == grant.pkce,
            "original PKCE proof required"
        );
        assert!(
            Secret::parse(field("client_secret").to_owned())
                .unwrap()
                .verifier()
                == self.secret.verifier(),
            "exact registered credential required"
        );
        if self.hold.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        let mut header = JwsHeader::new();
        header.set_key_id("owned-google");
        header.set_token_type("JWT");
        let token = jws::serialize_compact(
            &serde_json::to_vec(&grant.claims).unwrap(),
            &header,
            self.signer.as_ref(),
        )
        .unwrap();
        self.signed.fetch_add(1, Ordering::SeqCst);
        OidcTokenResponse::new(200,Some("application/json".into()),None,
            serde_json::to_vec(&json!({"id_token":token,"access_token":"unused-owned-token","token_type":"Bearer"})).unwrap())
    }
}
