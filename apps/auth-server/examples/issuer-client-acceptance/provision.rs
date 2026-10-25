//! Ordinary owned registration/key input using maintained producers only.
use super::{FixtureResult, key_input::OperatorKey};
use auth_core::{
    IssuerAuthority, IssuerClientRegistration, IssuerKeyPublication, IssuerNativeRefreshPolicy,
};
use auth_postgres::Postgres;
use sqlx::PgPool;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub(super) struct Provision {
    pub realm: Uuid,
    pub client: Uuid,
    pub native_client: Uuid,
    pub signing: OperatorKey,
    authority: IssuerAuthority,
    directory: PathBuf,
    replacement: Option<OperatorKey>,
    retained: Vec<OperatorKey>,
}
impl Provision {
    pub async fn new(pool: &PgPool, origin: &str, directory: &Path) -> FixtureResult<Self> {
        let store = Postgres::new(pool.clone());
        store.migrate().await?;
        let realm = Uuid::new_v4();
        store.ensure_realm(realm).await?;
        let authority = IssuerAuthority::new(realm, origin)?;
        let signing = OperatorKey::new(directory)?;
        let mut owned = Self {
            realm,
            client: Uuid::nil(),
            native_client: Uuid::nil(),
            signing,
            authority: authority.clone(),
            directory: directory.into(),
            replacement: None,
            retained: Vec::new(),
        };
        let now: i64 =
            sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
                .fetch_one(pool)
                .await?;
        store
            .publish_issuer_key(&IssuerKeyPublication::new(
                authority.clone(),
                owned.signing.key.public_key()?,
                now - 1_000_000,
                now + 3_600_000_000,
                now + 3_900_000_000,
            )?)
            .await?;
        let revision = store
            .activate_issuer_key(&authority, owned.signing.key.id())
            .await?;
        store.enable_issuer_signing(&authority, revision).await?;
        owned.client = store
            .configure_issuer_client(&IssuerClientRegistration::public(
                realm,
                Uuid::new_v4(),
                &["https://client.example/callback"],
            )?)
            .await?
            .client();
        let native = store
            .configure_issuer_client(&IssuerClientRegistration::public_native_refresh_loopback(
                realm,
                Uuid::new_v4(),
                &["http://127.0.0.1/callback"],
            )?)
            .await?;
        let policy = store
            .configure_issuer_native_refresh_policy(&IssuerNativeRefreshPolicy::new(
                authority,
                native.clone(),
                3600,
                600,
            )?)
            .await?;
        store.enable_issuer_native_refresh_policy(&policy).await?;
        owned.native_client = native.client();
        Ok(owned)
    }
    pub async fn publish_rotation(&mut self, pool: &PgPool) -> FixtureResult<u32> {
        if self.replacement.is_some() || !self.retained.is_empty() {
            return Err("one ordinary owned rollover only".into());
        }
        let store = Postgres::new(pool.clone());
        let current = store.load_issuer_signing(&self.authority).await?;
        let key = OperatorKey::new(&self.directory)?;
        let old = current.publication();
        store
            .publish_issuer_key(&IssuerKeyPublication::new(
                self.authority.clone(),
                key.key.public_key()?,
                old.sign_from_us(),
                old.sign_until_us(),
                old.verify_until_us(),
            )?)
            .await?;
        self.replacement = Some(key);
        // The caller waits the actual unchanged policy interval. Neither this
        // fixture nor production accepts a caller-selected ready_at/clock.
        Ok(auth_core::ISSUER_KEY_PROPAGATION_SECONDS as u32)
    }
    pub async fn activate_rotation(&mut self, pool: &PgPool) -> FixtureResult<()> {
        let next = self
            .replacement
            .as_ref()
            .ok_or("owned prepublished key required")?;
        Postgres::new(pool.clone())
            .activate_issuer_key(&self.authority, next.key.id())
            .await?;
        let next = self
            .replacement
            .take()
            .ok_or("owned prepublished key required")?;
        self.retained
            .push(std::mem::replace(&mut self.signing, next));
        Ok(())
    }
}
