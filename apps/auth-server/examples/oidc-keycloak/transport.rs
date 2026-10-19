use super::{FixtureResult, client, post, response};
use async_trait::async_trait;
use auth_core::{
    Error, OidcHttp, OidcHttpResponse, OidcTarget, OidcTokenHttp, OidcTokenRequest,
    OidcTokenResponse, Result,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use url::Url;

pub(super) struct Http {
    origin: String,
    address: SocketAddr,
    client: reqwest::Client,
    pub gets: AtomicUsize,
    pub posts: AtomicUsize,
}
impl Http {
    pub fn new(
        issuer: &str,
        address: SocketAddr,
        certificate: Vec<u8>,
    ) -> FixtureResult<Arc<Self>> {
        let issuer = Url::parse(issuer)?;
        if issuer.host_str() != Some("fixture.invalid")
            || !address.ip().is_loopback()
            || issuer.port_or_known_default() != Some(address.port())
            || certificate.len() > 4096
        {
            return Err("owned fixture target required".into());
        }
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(certificate))?;
        // Same production TLS builder, but this private fixture alone replaces
        // its public roots/address with our owned certificate/listener. Hostname,
        // SNI, peer, time/body bounds and redirect/proxy policy remain enabled.
        let client = client::builder(&issuer, &[address], roots)
            .map_err(|_| "fixture TLS configuration")?
            .build()?;
        Ok(Arc::new(Self {
            origin: issuer.origin().ascii_serialization(),
            address,
            client,
            gets: AtomicUsize::new(0),
            posts: AtomicUsize::new(0),
        }))
    }
    fn check(&self, target: &OidcTarget) -> Result<()> {
        if target.url().origin().ascii_serialization() != self.origin
            || target.addresses() != [SocketAddr::from(([8, 8, 8, 8], self.address.port()))]
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}
#[async_trait]
impl OidcHttp for Http {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if host != "fixture.invalid" || port != self.address.port() {
            return Err(Error::Unavailable);
        }
        Ok(vec![SocketAddr::from(([8, 8, 8, 8], port))])
    }
    async fn get(&self, target: &OidcTarget) -> Result<OidcHttpResponse> {
        self.check(target)?;
        self.gets.fetch_add(1, Ordering::SeqCst);
        response::download(&self.client, target.url(), &[self.address])
            .await
            .map_err(|_| Error::Unavailable)
    }
}
#[async_trait]
impl OidcTokenHttp for Http {
    async fn post(
        &self,
        target: &OidcTarget,
        request: &OidcTokenRequest,
    ) -> Result<OidcTokenResponse> {
        self.check(target)?;
        self.posts.fetch_add(1, Ordering::SeqCst);
        post::send(&self.client, target.url(), &[self.address], request)
            .await
            .map_err(|_| Error::Unavailable)
    }
}
