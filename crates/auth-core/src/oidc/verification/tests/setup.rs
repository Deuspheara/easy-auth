use crate::*;
use async_trait::async_trait;
use josekit::{
    jwk::KeyPair,
    jws::{self, ES256, JwsHeader, JwsSigner, PS256, RS256},
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
};
use tokio::sync::Notify;
use uuid::Uuid;

pub(super) const NOW_US: i64 = 1_700_000_000_000_000;
pub(super) struct Store {
    pub connection: OAuthConnection,
    state: Mutex<Option<Verifier>>,
    pub enabled: AtomicBool,
    pub available: AtomicBool,
    pub now: AtomicI64,
    pub checks: AtomicUsize,
    pub disable_at: AtomicUsize,
    pub hold_checks_from: AtomicUsize,
    pub check_entered: Notify,
    pub check_release: Notify,
}
#[async_trait]
impl OAuthTransactionRepository for Store {
    async fn save_oauth(&self, r: &OAuthRequest) -> Result<i64> {
        *self.state.lock().unwrap() = Some(r.state);
        Ok(NOW_US + 300_000_000)
    }
    async fn consume_oauth(&self, r: &OAuthRequest) -> Result<i64> {
        if self.state.lock().unwrap().take() != Some(r.state) {
            return Err(Error::Unauthorized);
        }
        Ok(NOW_US + 300_000_000)
    }
    async fn cancel_oauth(&self, _: &OAuthRequest) -> Result<()> {
        self.state.lock().unwrap().take();
        Ok(())
    }
}
#[async_trait]
impl OidcConnectionRepository for Store {
    async fn check_oidc_connection(&self, c: &OAuthConnection) -> Result<()> {
        if !self.available.load(Ordering::SeqCst) {
            return Err(Error::Unavailable);
        }
        if c != &self.connection || !self.enabled.load(Ordering::SeqCst) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
#[async_trait]
impl OidcExchangeRepository for Store {
    async fn check_oidc_exchange(&self, e: &OAuthExchange) -> Result<i64> {
        let check = self.checks.fetch_add(1, Ordering::SeqCst) + 1;
        if check >= self.hold_checks_from.load(Ordering::SeqCst) {
            self.check_entered.notify_one();
            self.check_release.notified().await;
        }
        if check == self.disable_at.load(Ordering::SeqCst) {
            self.enabled.store(false, Ordering::SeqCst);
        }
        self.check_oidc_connection(e.configuration()).await?;
        let now = self.now.load(Ordering::SeqCst);
        if now >= e.expires_us() {
            return Err(Error::Unauthorized);
        }
        Ok(now)
    }
}
pub(super) struct Http {
    pub metadata: Mutex<Value>,
    pub cache_seconds: AtomicUsize,
    pub hold_dns: AtomicBool,
    pub dns_entered: Notify,
    pub dns_release: Notify,
    pub keys: Mutex<Vec<u8>>,
    pub gets: AtomicUsize,
    pub hold: AtomicBool,
    pub entered: Notify,
    pub release: Notify,
}
#[async_trait]
impl OidcHttp for Http {
    async fn resolve(&self, _: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if self.hold_dns.load(Ordering::SeqCst) {
            self.dns_entered.notify_one();
            self.dns_release.notified().await;
        }
        Ok(vec![SocketAddr::from(([8, 8, 8, 8], port))])
    }
    async fn get(&self, target: &OidcTarget) -> Result<OidcHttpResponse> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        if self.hold.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        let body = if target.url().path().ends_with("openid-configuration") {
            serde_json::to_vec(&*self.metadata.lock().unwrap()).unwrap()
        } else {
            self.keys.lock().unwrap().clone()
        };
        Ok(OidcHttpResponse {
            status: 200,
            content_type: Some("application/json".into()),
            content_encoding: None,
            body,
            cache_seconds: self.cache_seconds.load(Ordering::SeqCst) as u64,
        })
    }
}
pub(super) struct Signing {
    pub signer: Box<dyn JwsSigner>,
    pub public: Value,
    pub kid: String,
}
impl Signing {
    pub fn with_header(&self, header: &[u8], claims: &Value) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        );
        // Malformed-header fixture only: real established-library signatures over
        // original duplicate/extension JSON that a map builder would normalize.
        let signature = self.signer.sign(input.as_bytes()).unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    pub fn new(algorithm: OidcSigningAlgorithm, kid: &str) -> Self {
        let (signer, mut public): (Box<dyn JwsSigner>, _) = match algorithm {
            OidcSigningAlgorithm::ES256 => {
                let k = ES256.generate_key_pair().unwrap();
                (
                    Box::new(ES256.signer_from_der(k.to_der_private_key()).unwrap()),
                    k.to_jwk_public_key(),
                )
            }
            OidcSigningAlgorithm::RS256 => {
                let k = RS256.generate_key_pair(2048).unwrap();
                (
                    Box::new(RS256.signer_from_der(k.to_der_private_key()).unwrap()),
                    k.to_jwk_public_key(),
                )
            }
            OidcSigningAlgorithm::PS256 => {
                let k = PS256.generate_key_pair(2048).unwrap();
                (
                    Box::new(PS256.signer_from_der(k.to_der_private_key()).unwrap()),
                    k.to_jwk_public_key(),
                )
            }
        };
        public.set_key_id(kid);
        public.set_algorithm(algorithm.name());
        public.set_key_use("sig");
        Self {
            signer,
            public: serde_json::to_value(public).unwrap(),
            kid: kid.into(),
        }
    }
    pub fn token(&self, claims: &Value) -> OidcIdToken {
        OidcIdToken::parse(self.raw(&serde_json::to_vec(claims).unwrap())).unwrap()
    }
    pub fn raw(&self, claims: &[u8]) -> String {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(&self.kid);
        jws::serialize_compact(claims, &header, self.signer.as_ref()).unwrap()
    }
}
pub(super) struct Fixture {
    pub store: Arc<Store>,
    pub http: Arc<Http>,
    pub documents: Arc<OidcDocuments>,
    pub verifier: Arc<OidcTokenVerifier>,
    pub key: Signing,
}
impl Fixture {
    pub fn new(algorithm: OidcSigningAlgorithm, additional: &[&str]) -> Self {
        let key = Signing::new(algorithm, "current");
        let connection = OAuthConnection::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "https://issuer.example",
            "client",
            "https://app.example/callback",
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        let store = Arc::new(Store {
            connection: connection.clone(),
            state: Mutex::new(None),
            enabled: AtomicBool::new(true),
            available: AtomicBool::new(true),
            now: AtomicI64::new(NOW_US),
            checks: AtomicUsize::new(0),
            disable_at: AtomicUsize::new(usize::MAX),
            hold_checks_from: AtomicUsize::new(usize::MAX),
            check_entered: Notify::new(),
            check_release: Notify::new(),
        });
        let http = Arc::new(Http {
            metadata: Mutex::new(
                json!({"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/keys","authorization_response_iss_parameter_supported":true,"code_challenge_methods_supported":["S256"]}),
            ),
            cache_seconds: AtomicUsize::new(300),
            hold_dns: AtomicBool::new(false),
            dns_entered: Notify::new(),
            dns_release: Notify::new(),
            keys: Mutex::new(serde_json::to_vec(&json!({"keys":[key.public.clone()]})).unwrap()),
            gets: AtomicUsize::new(0),
            hold: AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let documents = Arc::new(
            OidcDocuments::new(
                connection,
                &["https://issuer.example"],
                store.clone(),
                http.clone(),
            )
            .unwrap(),
        );
        let policy = OidcVerificationPolicy::new(&[algorithm], additional).unwrap();
        let verifier = Arc::new(OidcTokenVerifier::new(
            documents.clone(),
            store.clone(),
            policy,
        ));
        Self {
            store,
            http,
            documents,
            verifier,
            key,
        }
    }
    pub async fn exchange(&self) -> (OAuthExchange, Value) {
        let transactions =
            OAuthTransactions::new(self.store.connection.clone(), self.store.clone());
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-test",
            purpose: OAuthPurpose::SignIn,
        };
        let start = transactions.begin(&intent).await.unwrap();
        let claims = json!({"iss":self.store.connection.issuer(),"sub":"subject","aud":"client","iat":NOW_US/1_000_000,"exp":NOW_US/1_000_000+60,"nonce":start.proof.nonce().expose()});
        let exchange = transactions
            .consume(
                &intent,
                &start.state,
                start.proof,
                OAuthCallback {
                    redirect: self.store.connection.redirect(),
                    issuer: Some(self.store.connection.issuer()),
                },
            )
            .await
            .unwrap();
        (exchange, claims)
    }
    pub fn gets(&self) -> usize {
        self.http.gets.load(Ordering::SeqCst)
    }
}
