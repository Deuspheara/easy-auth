use super::{
    OIDC_FETCH_TIMEOUT, OidcConnectionRepository, OidcDiscovery, OidcHttp, OidcHttpResponse,
    OidcJwksDocument, OidcTarget, metadata,
    policy::{Policy, literal},
};
use crate::{Error, OAuthConnection, Result};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::Instant};
use url::Url;

const MAX_CACHE_SECONDS: u64 = 300;
const MIN_NETWORK_INTERVAL: Duration = Duration::from_secs(1);
const MIN_FORCED_KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

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
    refreshed: Option<Instant>,
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
    #[cfg(feature = "oidc-verification")]
    pub(super) fn connection(&self) -> &OAuthConnection {
        &self.connection
    }

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
        tokio::time::timeout(OIDC_FETCH_TIMEOUT, self.load_keys(None))
            .await
            .map_err(|_| Error::Unavailable)?
    }

    /// Request a bounded refresh after a verifier found an unknown key ID in this
    /// exact snapshot. A newer cached snapshot is reused without another fetch.
    /// This operation verifies no signature or claim and never authenticates.
    pub async fn refresh_jwks(&self, observed: &OidcJwksDocument) -> Result<OidcJwksDocument> {
        tokio::time::timeout(OIDC_FETCH_TIMEOUT, self.load_keys(Some(observed)))
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

    async fn load_keys(&self, observed: Option<&OidcJwksDocument>) -> Result<OidcJwksDocument> {
        let discovery = self.load_discovery().await?;
        self.load_keys_from(&discovery, observed).await
    }

    #[cfg(feature = "oidc-verification")]
    pub(super) async fn keys_from_discovery(
        &self,
        discovery: &OidcDiscovery,
        observed: Option<&OidcJwksDocument>,
    ) -> Result<OidcJwksDocument> {
        tokio::time::timeout(OIDC_FETCH_TIMEOUT, self.load_keys_from(discovery, observed))
            .await
            .map_err(|_| Error::Unavailable)?
    }

    async fn load_keys_from(
        &self,
        discovery: &OidcDiscovery,
        observed: Option<&OidcJwksDocument>,
    ) -> Result<OidcJwksDocument> {
        self.repository
            .check_oidc_connection(&self.connection)
            .await?;
        let mut cache = self.keys.try_lock().map_err(|_| Error::RateLimited)?;
        if let Some(cached) = cache
            .cached
            .as_ref()
            .filter(|cached| cached.expires > Instant::now() && cached.url == discovery.jwks_uri())
            && observed.is_none_or(|previous| !cached.value.same_snapshot(previous))
        {
            return Ok(cached.value.clone());
        }
        if observed.is_some()
            && cache.refreshed.is_some_and(|previous| {
                Instant::now().duration_since(previous) < MIN_FORCED_KEY_REFRESH_INTERVAL
            })
        {
            return Err(Error::RateLimited);
        }
        admit_fetch(&mut cache.attempted)?;
        if observed.is_some() {
            // Failed refreshes spend the same fixed budget; key IDs never become
            // map keys, so attacker-selected IDs cannot grow cache/admission state.
            cache.refreshed = Some(Instant::now());
        }
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
        let target = self.resolve_target(url).await?;
        self.http.get(&target).await
    }

    pub(super) async fn resolve_target(&self, url: Url) -> Result<OidcTarget> {
        let port = url.port_or_known_default().ok_or(Error::Unavailable)?;
        let addresses = if let Some(ip) = literal(&url) {
            vec![SocketAddr::new(ip, port)]
        } else {
            self.http
                .resolve(url.host_str().ok_or(Error::Unavailable)?, port)
                .await?
        };
        self.policy.target(url, addresses)
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
