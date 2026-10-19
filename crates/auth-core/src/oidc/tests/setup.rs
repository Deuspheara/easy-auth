use crate::{
    Error, OAuthConnection, OAuthMixupDefense, OidcConnectionRepository, OidcDocuments, OidcHttp,
    OidcHttpResponse, OidcTarget, Result,
};
use async_trait::async_trait;
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::sync::Notify;
use uuid::Uuid;

pub(super) struct Registry {
    pub connection: OAuthConnection,
    pub enabled: AtomicBool,
}
#[async_trait]
impl OidcConnectionRepository for Registry {
    async fn check_oidc_connection(&self, connection: &OAuthConnection) -> Result<()> {
        if connection != &self.connection || !self.enabled.load(Ordering::SeqCst) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

pub(super) struct Http {
    pub answers: Mutex<Vec<SocketAddr>>,
    pub metadata: Mutex<Vec<u8>>,
    pub keys: Mutex<Vec<u8>>,
    pub status: AtomicUsize,
    pub age: AtomicUsize,
    pub gets: AtomicUsize,
    pub resolutions: AtomicUsize,
    pub targets: Mutex<Vec<(String, Vec<SocketAddr>)>>,
    pub hold: AtomicBool,
    pub stall_dns: AtomicBool,
    pub entered: Notify,
    pub release: Notify,
}
#[async_trait]
impl OidcHttp for Http {
    async fn resolve(&self, _: &str, _: u16) -> Result<Vec<SocketAddr>> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        if self.stall_dns.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        Ok(self.answers.lock().unwrap().clone())
    }
    async fn get(&self, target: &OidcTarget) -> Result<OidcHttpResponse> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.targets.lock().unwrap().push((
            target.url().as_str().to_owned(),
            target.addresses().to_owned(),
        ));
        if self.hold.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        let discovery = target.url().path().ends_with("openid-configuration");
        Ok(OidcHttpResponse {
            status: self.status.load(Ordering::SeqCst) as u16,
            content_type: Some("application/json".into()),
            content_encoding: None,
            body: if discovery {
                self.metadata.lock().unwrap().clone()
            } else {
                self.keys.lock().unwrap().clone()
            },
            cache_seconds: self.age.load(Ordering::SeqCst) as u64,
        })
    }
}

pub(super) struct Fixture {
    pub registry: Arc<Registry>,
    pub http: Arc<Http>,
    pub documents: Arc<OidcDocuments>,
}
impl Fixture {
    pub fn new() -> Self {
        let connection = OAuthConnection::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "https://issuer.example/tenant/",
            "client",
            "https://app.example/callback",
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        let registry = Arc::new(Registry {
            connection: connection.clone(),
            enabled: AtomicBool::new(true),
        });
        let http = Arc::new(Http {
            answers: Mutex::new(vec!["8.8.8.8:443".parse().unwrap()]),
            metadata: Mutex::new(valid_metadata()),
            // Envelope-only fixture, deliberately not evidence of a valid signing key.
            keys: Mutex::new(br#"{"keys":[{"kid":"envelope-fixture"}]}"#.to_vec()),
            status: AtomicUsize::new(200),
            age: AtomicUsize::new(600),
            gets: AtomicUsize::new(0),
            resolutions: AtomicUsize::new(0),
            targets: Mutex::new(Vec::new()),
            hold: AtomicBool::new(false),
            stall_dns: AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let documents = Arc::new(
            OidcDocuments::new(
                connection,
                &["https://issuer.example"],
                registry.clone(),
                http.clone(),
            )
            .unwrap(),
        );
        Self {
            registry,
            http,
            documents,
        }
    }
    pub fn gets(&self) -> usize {
        self.http.gets.load(Ordering::SeqCst)
    }
}

pub(super) fn valid_metadata() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "issuer":"https://issuer.example/tenant/",
        "authorization_endpoint":"https://issuer.example/authorize?locale=fr",
        "token_endpoint":"https://issuer.example/token", "jwks_uri":"https://issuer.example/keys",
        "code_challenge_methods_supported":["S256"],"authorization_response_iss_parameter_supported":true
    })).unwrap()
}
