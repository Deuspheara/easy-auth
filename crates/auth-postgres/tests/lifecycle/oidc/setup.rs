use crate::support::realm;
use async_trait::async_trait;
use auth_core::{
    OAuthConnection, OAuthMixupDefense, OidcDocuments, OidcHttp, OidcHttpResponse, OidcTarget,
    Result,
};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::sync::Notify;
use uuid::Uuid;

pub(super) struct Http {
    pub gets: AtomicUsize,
    pub hold: AtomicBool,
    pub entered: Notify,
    pub release: Notify,
}
#[async_trait]
impl OidcHttp for Http {
    async fn resolve(&self, _: &str, port: u16) -> Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::from(([8, 8, 8, 8], port))])
    }
    async fn get(&self, target: &OidcTarget) -> Result<OidcHttpResponse> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        if self.hold.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        // Protocol/envelope fixtures only; no actual provider token/signing key.
        let body = if target.url().path().ends_with("openid-configuration") {
            serde_json::json!({"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/authorize",
                "token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/keys",
                "authorization_response_iss_parameter_supported":true})
        } else {
            serde_json::json!({"keys":[{"kid":"envelope-fixture"}]})
        };
        Ok(OidcHttpResponse {
            status: 200,
            content_type: Some("application/json".into()),
            content_encoding: None,
            body: serde_json::to_vec(&body).unwrap(),
            cache_seconds: 120,
        })
    }
}

pub(super) struct Fixture {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub connection: OAuthConnection,
    pub http: Arc<Http>,
    pub documents: Arc<OidcDocuments>,
}
impl Fixture {
    #[cfg(feature = "oidc-verification")]
    pub async fn exchange(&self, purpose: auth_core::OAuthPurpose) -> auth_core::OAuthExchange {
        let browser = auth_core::Secret::generate().unwrap();
        let intent = auth_core::OAuthIntent {
            browser: &browser,
            source: "oidc-owned-test",
            purpose,
        };
        let flow = auth_core::OAuthTransactions::new(self.connection.clone(), self.store.clone());
        let start = flow.begin(&intent).await.unwrap();
        flow.consume(
            &intent,
            &start.state,
            start.proof,
            auth_core::OAuthCallback {
                redirect: self.connection.redirect(),
                issuer: Some(self.connection.issuer()),
            },
        )
        .await
        .unwrap()
    }

    pub async fn new(pool: PgPool) -> Self {
        let (store, realm) = realm(pool.clone()).await;
        let id = Uuid::new_v4();
        let input = OAuthConnection::new(
            realm,
            id,
            Uuid::new_v4(),
            "https://issuer.example",
            "provider-client",
            &format!("https://app.example/callback/{id}"),
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        let connection = store.configure_oauth_connection(&input).await.unwrap();
        let store = Arc::new(store);
        let http = Arc::new(Http {
            gets: AtomicUsize::new(0),
            hold: AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let documents = Arc::new(
            OidcDocuments::new(
                connection.clone(),
                &["https://issuer.example"],
                store.clone(),
                http.clone(),
            )
            .unwrap(),
        );
        Self {
            pool,
            store,
            connection,
            http,
            documents,
        }
    }
    pub fn documents_for(&self, connection: OAuthConnection) -> OidcDocuments {
        OidcDocuments::new(
            connection,
            &["https://issuer.example"],
            self.store.clone(),
            self.http.clone(),
        )
        .unwrap()
    }
    pub fn gets(&self) -> usize {
        self.http.gets.load(Ordering::SeqCst)
    }
}
