use super::{
    OIDC_FETCH_TIMEOUT, OidcConnectionRepository, OidcDiscovery, OidcHttp, OidcHttpResponse,
    OidcJwksDocument, metadata,
    policy::{Policy, literal},
};
use crate::{Error, OAuthConnection, Result};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::Instant};
use url::Url;

const MAX_CACHE_SECONDS: u64 = 300;
const MIN_NETWORK_INTERVAL: Duration = Duration::from_secs(1);

struct DiscoveryCache {
    expires: Instant,
    value: OidcDiscovery,
}
struct KeysCache {
    expires: Instant,
    url: String,
    value: OidcJwksDocument,
}

#[derive(Default)]
struct DiscoverySlot {
    cached: Option<DiscoveryCache>,
    attempted: Option<Instant>,
}
#[derive(Default)]
struct KeysSlot {
    cached: Option<KeysCache>,
    attempted: Option<Instant>,
}

/// One immutable realm/connection/client/revision and two bounded cache slots.
/// No caller-supplied URL, token `jku`, provider identity or session is accepted.
pub struct OidcDocuments {
    connection: OAuthConnection,
    policy: Policy,
    repository: Arc<dyn OidcConnectionRepository>,
    http: Arc<dyn OidcHttp>,
    discovery: Mutex<DiscoverySlot>,
    keys: Mutex<KeysSlot>,
}

impl OidcDocuments {
    pub fn new(
        connection: OAuthConnection,
        origins: &[&str],
        repository: Arc<dyn OidcConnectionRepository>,
        http: Arc<dyn OidcHttp>,
    ) -> Result<Self> {
        let policy = Policy::new(&connection, origins)?;
        Ok(Self {
            connection,
            policy,
            repository,
            http,
            discovery: Mutex::new(DiscoverySlot::default()),
            keys: Mutex::new(KeysSlot::default()),
        })
    }

    pub async fn discovery(&self) -> Result<OidcDiscovery> {
        tokio::time::timeout(OIDC_FETCH_TIMEOUT, self.load_discovery())
            .await
            .map_err(|_| Error::Unavailable)?
    }

    /// Raw bounded envelope for a future reviewed JOSE verifier. These bytes do
    /// not establish a trusted key, signature, algorithm, claim or authentication.
    pub async fn jwks(&self) -> Result<OidcJwksDocument> {
        tokio::time::timeout(OIDC_FETCH_TIMEOUT, self.load_keys())
            .await
            .map_err(|_| Error::Unavailable)?
    }

    async fn load_discovery(&self) -> Result<OidcDiscovery> {
        self.repository
            .check_oidc_connection(&self.connection)
            .await?;
        // A fetch owns only this in-memory slot, never a database lock. Contenders
        // fail promptly rather than queue unbounded requests behind network I/O.
        let mut cache = self.discovery.try_lock().map_err(|_| Error::RateLimited)?;
        if let Some(cached) = cache
            .cached
            .as_ref()
            .filter(|cached| cached.expires > Instant::now())
        {
            return Ok(cached.value.clone());
        }
        admit_fetch(&mut cache.attempted)?;
        let response = self.fetch(self.policy.discovery_url()?).await?;
        let received = Instant::now();
        let age = response.cache_seconds.min(MAX_CACHE_SECONDS);
        let value = metadata::discovery(response, &self.connection, &self.policy)?;
        self.repository
            .check_oidc_connection(&self.connection)
            .await?;
        cache.cached = Some(DiscoveryCache {
            expires: received + Duration::from_secs(age),
            value: value.clone(),
        });
        Ok(value)
    }

    async fn load_keys(&self) -> Result<OidcJwksDocument> {
        let discovery = self.load_discovery().await?;
        self.repository
            .check_oidc_connection(&self.connection)
            .await?;
        let mut cache = self.keys.try_lock().map_err(|_| Error::RateLimited)?;
        if let Some(cached) = cache
            .cached
            .as_ref()
            .filter(|cached| cached.expires > Instant::now() && cached.url == discovery.jwks_uri())
        {
            return Ok(cached.value.clone());
        }
        admit_fetch(&mut cache.attempted)?;
        let response = self
            .fetch(self.policy.endpoint(discovery.jwks_uri())?)
            .await?;
        let received = Instant::now();
        let age = response.cache_seconds.min(MAX_CACHE_SECONDS);
        let value = metadata::jwks(response)?;
        self.repository
            .check_oidc_connection(&self.connection)
            .await?;
        cache.cached = Some(KeysCache {
            expires: received + Duration::from_secs(age),
            url: discovery.jwks_uri().to_owned(),
            value: value.clone(),
        });
        Ok(value)
    }

    async fn fetch(&self, url: Url) -> Result<OidcHttpResponse> {
        let port = url.port_or_known_default().ok_or(Error::Unavailable)?;
        let addresses = if let Some(ip) = literal(&url) {
            vec![SocketAddr::new(ip, port)]
        } else {
            self.http
                .resolve(url.host_str().ok_or(Error::Unavailable)?, port)
                .await?
        };
        let target = self.policy.target(url, addresses)?;
        self.http.get(&target).await
    }
}

fn admit_fetch(attempted: &mut Option<Instant>) -> Result<()> {
    let now = Instant::now();
    if attempted.is_some_and(|previous| now.duration_since(previous) < MIN_NETWORK_INTERVAL) {
        return Err(Error::RateLimited);
    }
    // Failed/malformed/non-cacheable attempts also spend the short fetch budget.
    *attempted = Some(now);
    Ok(())
}
