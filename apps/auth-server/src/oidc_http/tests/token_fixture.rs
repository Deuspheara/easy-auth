use super::{
    super::{client, response::Failure},
    tls_fixture::Fixture,
};
use async_trait::async_trait;
use auth_core::*;
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub(super) struct Store {
    pub connection: OAuthConnection,
    state: Mutex<Option<Verifier>>,
}
impl Store {
    pub fn new(f: &Fixture) -> Arc<Self> {
        Arc::new(Self {
            connection: OAuthConnection::new(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                f.url("").as_str(),
                "client",
                "https://app.example/callback",
                OAuthMixupDefense::RequireIssuer,
            )
            .unwrap(),
            state: Mutex::new(None),
        })
    }
    pub async fn exchange(self: &Arc<Self>) -> OAuthExchange {
        let transactions = OAuthTransactions::new(self.connection.clone(), self.clone());
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-tls-fixture",
            purpose: OAuthPurpose::SignIn,
        };
        let start = transactions.begin(&intent).await.unwrap();
        transactions
            .consume(
                &intent,
                &start.state,
                start.proof,
                OAuthCallback {
                    redirect: self.connection.redirect(),
                    issuer: Some(self.connection.issuer()),
                },
            )
            .await
            .unwrap()
    }
}
fn deadline() -> i64 {
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64)
        + 300_000_000
}
#[async_trait]
impl OAuthTransactionRepository for Store {
    async fn save_oauth(&self, r: &OAuthRequest) -> Result<i64> {
        *self.state.lock().unwrap() = Some(r.state);
        Ok(deadline())
    }
    async fn consume_oauth(&self, r: &OAuthRequest) -> Result<i64> {
        if self.state.lock().unwrap().take() != Some(r.state) {
            return Err(Error::Unauthorized);
        }
        Ok(deadline())
    }
    async fn cancel_oauth(&self, _: &OAuthRequest) -> Result<()> {
        self.state.lock().unwrap().take();
        Ok(())
    }
}
#[async_trait]
impl OidcConnectionRepository for Store {
    async fn check_oidc_connection(&self, c: &OAuthConnection) -> Result<()> {
        if c != &self.connection {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
#[async_trait]
impl OidcExchangeRepository for Store {
    async fn check_oidc_exchange(&self, e: &OAuthExchange) -> Result<i64> {
        self.check_oidc_connection(e.configuration()).await?;
        Ok(deadline() - 300_000_000)
    }
}

// Private component fixture only: policy resolves the configured hostname to a
// public target; the actual checked TLS client pins our owned loopback listener.
// No production override/root/IP bypass or public request constructor is added.
pub(super) struct Http {
    pub url: url::Url,
    address: SocketAddr,
    roots: rustls::RootCertStore,
    pub failure: Mutex<Option<Failure>>,
}
impl Http {
    pub fn new(f: &Fixture, path: &str) -> Arc<Self> {
        Arc::new(Self {
            url: f.url(path),
            address: f.address,
            roots: f.roots(),
            failure: Mutex::new(None),
        })
    }
}
#[async_trait]
impl OidcHttp for Http {
    async fn resolve(&self, _: &str, port: u16) -> Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::from(([8, 8, 8, 8], port))])
    }
    async fn get(&self, _: &OidcTarget) -> Result<OidcHttpResponse> {
        let issuer = self.url.join("/").unwrap();
        Ok(OidcHttpResponse {status:200,content_type:Some("application/json".into()),content_encoding:None,cache_seconds:300,
            body:serde_json::to_vec(&json!({"issuer":issuer.as_str(),"authorization_endpoint":issuer.join("authorize").unwrap(),
                "token_endpoint":self.url.as_str(),"jwks_uri":issuer.join("keys").unwrap(),
                "authorization_response_iss_parameter_supported":true,"code_challenge_methods_supported":["S256"]})).unwrap()})
    }
}
#[async_trait]
impl OidcTokenHttp for Http {
    async fn post(
        &self,
        target: &OidcTarget,
        request: &OidcTokenRequest,
    ) -> Result<OidcTokenResponse> {
        assert!(target.url() == &self.url);
        assert_eq!(
            target.addresses(),
            [SocketAddr::from(([8, 8, 8, 8], self.address.port()))]
        );
        let builder = client::builder(&self.url, &[self.address], self.roots.clone()).unwrap();
        let builder = if self.url.path() == "/stall" {
            builder.timeout(Duration::from_millis(200))
        } else {
            builder
        };
        let client = builder.build().unwrap();
        super::super::super::post::send(&client, &self.url, &[self.address], request)
            .await
            .map_err(|failure| {
                *self.failure.lock().unwrap() = Some(failure);
                Error::Unavailable
            })
    }
}
