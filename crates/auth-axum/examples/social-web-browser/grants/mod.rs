mod http;
mod observations;
mod routes;
use super::{FixtureResult, apple_provider::Provider};
use auth_core::*;
use auth_postgres::Postgres;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
pub(super) use routes::routes;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

// Fresh owned-fixture key only. Never accept a browser key or use this harness
// against retained data. The normal existing generator supplies all entropy.
pub(super) fn vault() -> FixtureResult<Arc<AppleGrantVault>> {
    let random = Secret::generate()?;
    Ok(Arc::new(AppleGrantVault::new(
        AppleGrantKey::new(Uuid::new_v4(), URL_SAFE_NO_PAD.decode(random.expose())?)?,
        vec![],
    )?))
}
pub(super) struct Fixture {
    pool: PgPool,
    realm: Uuid,
    worker: AppleGrantRevoker,
    http: Arc<http::Http>,
}
impl Fixture {
    pub fn new(
        pool: PgPool,
        realm: Uuid,
        source: OAuthConnection,
        signer: Arc<AppleClientSecretSigner>,
        vault: Arc<AppleGrantVault>,
        store: Arc<Postgres>,
        provider: Arc<Provider>,
    ) -> FixtureResult<Arc<Self>> {
        let http = http::Http::new(provider.clone());
        let worker = AppleGrantRevoker::new(
            source,
            store.clone(),
            signer,
            vault,
            store,
            provider,
            http.clone(),
        )?;
        Ok(Arc::new(Self {
            pool,
            realm,
            worker,
            http,
        }))
    }
}
