//! Private fixed web/native client operations; credentials never leave the pipe owner.
use super::{FixtureResult, provision::Provision, transport};
use auth_core::{
    OidcClient, OidcClientAuthentication, OidcClientAuthorization, OidcClientConfiguration,
    OidcClientCredential, OidcClientError,
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
};

pub(super) struct Clients {
    web: OidcClient,
    native: OidcClient,
    http: Arc<transport::Http>,
    pending: Option<Pending>,
    refresh: Option<OidcClientCredential>,
    issuer: String,
    web_id: uuid::Uuid,
    native_id: uuid::Uuid,
}
enum Pending {
    Web(OidcClientAuthorization),
    Native(OidcClientAuthorization),
}
impl Clients {
    pub fn new(
        config: &Value,
        provision: &Provision,
        http: Arc<transport::Http>,
    ) -> FixtureResult<Self> {
        let issuer = config["issuer"].as_str().ok_or("owned issuer required")?;
        let callback: SocketAddr = config["native_listener"]
            .as_str()
            .ok_or("owned actual native listener required")?
            .parse()?;
        let web = OidcClient::new(
            OidcClientConfiguration::web(
                issuer,
                provision.client,
                "https://client.example/callback",
                OidcClientAuthentication::Public,
            )?,
            http.clone(),
            http.clone(),
        )?;
        let native = OidcClient::new(
            OidcClientConfiguration::native(
                issuer,
                provision.native_client,
                callback,
                "/callback",
                true,
            )?,
            http.clone(),
            http.clone(),
        )?;
        Ok(Self {
            web,
            native,
            http,
            pending: None,
            refresh: None,
            issuer: issuer.into(),
            web_id: provision.client,
            native_id: provision.native_client,
        })
    }
    pub async fn command(&mut self, command: &Value) -> FixtureResult<Value> {
        match command["command"].as_str() {
            Some("authorize") => self.authorize(false).await,
            Some("authorize_native") => self.authorize(true).await,
            Some("complete") => {
                self.complete(
                    command["callback"]
                        .as_str()
                        .ok_or("actual callback required")?,
                )
                .await
            }
            Some("refresh") => self.refresh().await,
            _ => Err("unsupported owned command".into()),
        }
    }
    async fn authorize(&mut self, native: bool) -> FixtureResult<Value> {
        if self.pending.is_some() {
            return Err("owned operation already retained".into());
        }
        let operation = if native {
            self.native.authorize().await?
        } else {
            self.web.authorize().await?
        };
        let response = json!({"authorization_url":operation.authorization_url()});
        self.pending = Some(if native {
            Pending::Native(operation)
        } else {
            Pending::Web(operation)
        });
        Ok(response)
    }
    async fn complete(&mut self, actual: &str) -> FixtureResult<Value> {
        let pending = self
            .pending
            .take()
            .ok_or("owned pending operation required")?;
        let before = self.http.posts.load(Ordering::SeqCst);
        let (native, result) = match pending {
            Pending::Web(operation) => (false, self.web.complete(operation, actual).await),
            Pending::Native(operation) => (true, self.native.complete(operation, actual).await),
        };
        let posts = self.http.posts.load(Ordering::SeqCst) - before;
        match result {
            Ok(mut tokens) => {
                let identity = tokens.identity();
                let expected = if native { self.native_id } else { self.web_id };
                if identity.issuer() != self.issuer
                    || identity.client() != expected
                    || identity.authenticated_at().is_none()
                    || tokens.refresh_token().is_some() != native
                {
                    return Err("owned SDK projection mismatch".into());
                }
                let response = json!({"verified":true,"posts":posts,"subject_pairwise":uuid::Uuid::parse_str(identity.subject()).is_ok(),"native":native});
                self.refresh = tokens.take_refresh_token();
                Ok(response)
            }
            Err(OidcClientError::Denied) => Ok(json!({"denied":true,"posts":posts})),
            Err(_) => Err("owned SDK operation failed".into()),
        }
    }
    async fn refresh(&mut self) -> FixtureResult<Value> {
        let token = self
            .refresh
            .take()
            .ok_or("owned refresh generation required")?;
        let before = self.http.posts.load(Ordering::SeqCst);
        match self.native.refresh(token).await {
            Ok(mut result) => {
                self.refresh = result.take_refresh_token();
                if self.refresh.is_none() {
                    return Err("owned replacement required".into());
                }
                Ok(json!({"rotated":true,"posts":self.http.posts.load(Ordering::SeqCst)-before}))
            }
            Err(OidcClientError::InvalidGrant) => Ok(
                json!({"invalid_grant":true,"posts":self.http.posts.load(Ordering::SeqCst)-before}),
            ),
            Err(_) => Err("owned SDK rotation failed".into()),
        }
    }
}
