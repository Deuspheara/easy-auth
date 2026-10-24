//! Ordinary owned registration/key input using maintained producers only.
use super::FixtureResult;
use auth_core::{
    IssuerAuthority, IssuerClientRegistration, IssuerKeyPublication, IssuerSigningKey,
};
use auth_postgres::Postgres;
use josekit::{jwk::KeyPair, jws::RS256};
use sqlx::PgPool;
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) struct Provision {
    pub realm: Uuid,
    pub client: Uuid,
    pub key: Uuid,
    pub key_file: PathBuf,
}
impl Provision {
    pub async fn new(pool: &PgPool, origin: &str, directory: &Path) -> FixtureResult<Self> {
        let store = Postgres::new(pool.clone());
        store.migrate().await?;
        let realm = Uuid::new_v4();
        store.ensure_realm(realm).await?;
        let authority = IssuerAuthority::new(realm, origin)?;
        let pair = RS256.generate_key_pair(2048)?;
        let pem = Zeroizing::new(pair.to_pem_private_key());
        let key_id = Uuid::new_v4();
        let key = IssuerSigningKey::from_pkcs8_pem(key_id, String::from_utf8(pem.to_vec())?)?;
        let key_file = directory.join(format!("issuer-{}.pem", key_id.simple()));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&key_file)?;
        output.write_all(&pem)?;
        drop(output);
        let mut owned = Self {
            realm,
            client: Uuid::nil(),
            key: key_id,
            key_file,
        };
        let now: i64 =
            sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
                .fetch_one(pool)
                .await?;
        store
            .publish_issuer_key(&IssuerKeyPublication::new(
                authority.clone(),
                key.public_key()?,
                now - 1_000_000,
                now + 3_600_000_000,
                now + 3_900_000_000,
            )?)
            .await?;
        let revision = store.activate_issuer_key(&authority, key.id()).await?;
        store.enable_issuer_signing(&authority, revision).await?;
        owned.client = store
            .configure_issuer_client(&IssuerClientRegistration::public(
                realm,
                Uuid::new_v4(),
                &["https://client.example/callback"],
            )?)
            .await?
            .client();
        Ok(owned)
    }
}
impl Drop for Provision {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.key_file);
    }
}
