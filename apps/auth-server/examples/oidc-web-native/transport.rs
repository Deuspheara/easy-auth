use super::{FixtureResult, transport_port::Http};
use async_trait::async_trait;
use auth_core::{
    OidcHttp, OidcHttpResponse, OidcTarget, OidcTokenHttp, OidcTokenRequest, OidcTokenResponse,
    Result,
};
use serde_json::Value;
use std::sync::{Arc, OnceLock};

static OWNED: OnceLock<Arc<Http>> = OnceLock::new();

// Only this example crate substitutes the factory's concrete transport name.
// Application/settings sources are unchanged; production has no such initializer,
// private root, address override or configurable transport injection.
#[derive(Clone)]
pub(super) struct OwnedHttps(Arc<Http>);
impl OwnedHttps {
    pub(super) fn new() -> Self {
        Self(
            OWNED
                .get()
                .expect("owned transport initialized before factory")
                .clone(),
        )
    }
}
pub(super) fn initialize(config: &Value) -> FixtureResult<()> {
    let issuer = std::env::var("AUTH_OIDC_ISSUER")?;
    if config["issuer"].as_str() != Some(&issuer) {
        return Err("owned issuer must match actual settings".into());
    }
    let http = Http::new(
        &issuer,
        config["address"]
            .as_str()
            .ok_or("owned TLS address")?
            .parse()?,
        serde_json::from_value(config["certificate_der"].clone())?,
    )?;
    OWNED
        .set(http)
        .map_err(|_| "owned transport already initialized")?;
    Ok(())
}
#[async_trait]
impl OidcHttp for OwnedHttps {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>> {
        self.0.resolve(host, port).await
    }
    async fn get(&self, target: &OidcTarget) -> Result<OidcHttpResponse> {
        self.0.get(target).await
    }
}
#[async_trait]
impl OidcTokenHttp for OwnedHttps {
    async fn post(
        &self,
        target: &OidcTarget,
        request: &OidcTokenRequest,
    ) -> Result<OidcTokenResponse> {
        self.0.post(target, request).await
    }
}
