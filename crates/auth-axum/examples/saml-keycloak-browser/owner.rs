use super::{
    FixtureResult, application,
    configuration::{Jit, Pin, Setup, trust},
    observations::Observations,
};
use auth_core::{SamlIdentityPolicy, SamlRegistration};
use auth_postgres::Postgres;
use axum::Router;
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{RwLock, oneshot},
    task::JoinHandle,
};
use uuid::Uuid;

pub(super) struct Owner {
    store: Arc<Postgres>,
    pool: PgPool,
    observations: Arc<Observations>,
    origin: String,
    issuer: String,
    realms: [Uuid; 2],
    connection: Uuid,
    client: Uuid,
    policies: [Option<SamlIdentityPolicy>; 2],
    selected: usize,
    current: Arc<RwLock<Router>>,
    shutdown: oneshot::Sender<()>,
    server: JoinHandle<Result<(), std::io::Error>>,
}
impl Owner {
    pub async fn new(pool: PgPool, setup: Setup) -> FixtureResult<(Self, String)> {
        setup.validate()?;
        let store = Arc::new(Postgres::new(pool.clone()));
        store.migrate().await?;
        let realms = [Uuid::new_v4(), Uuid::new_v4()];
        for realm in realms {
            store.ensure_realm(realm).await?;
        }
        let current = Arc::new(RwLock::new(Router::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?.to_string();
        let (shutdown, receiver) = oneshot::channel();
        let app = application::serve(current.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = receiver.await;
                })
                .await
        });
        let observations = Arc::new(Observations::new(store.clone()));
        let mut owner = Self {
            store,
            pool,
            observations,
            origin: setup.origin,
            issuer: setup.issuer,
            realms,
            connection: Uuid::new_v4(),
            client: Uuid::new_v4(),
            policies: [None, None],
            selected: 0,
            current,
            shutdown,
            server,
        };
        // A preparation failure must stop the listener before database cleanup.
        if let Err(error) = owner.configure(0, &setup.certificates, setup.jit).await {
            owner.close().await?;
            return Err(error);
        }
        Ok((owner, address))
    }
    pub async fn configure(&mut self, index: usize, pins: &[Pin], jit: Jit) -> FixtureResult<()> {
        let realm = *self.realms.get(index).ok_or("unknown owned realm")?;
        let reg = SamlRegistration::unsigned_redirect(
            realm,
            self.connection,
            self.client,
            "urn:example:sp",
            &self.issuer,
            &format!("{}/protocol/saml", self.issuer),
            &format!("{}/saml/acs", self.origin),
        )?;
        let policy = self
            .store
            .configure_saml_identity_policy(
                &SamlIdentityPolicy::new(reg).with_jit(jit.into()),
                &trust(pins)?,
            )
            .await?;
        self.policies[index] = Some(policy);
        self.select(index).await
    }
    pub async fn select(&mut self, index: usize) -> FixtureResult<()> {
        let policy = self
            .policies
            .get(index)
            .and_then(Option::as_ref)
            .ok_or("owned realm unconfigured")?
            .clone();
        let app = application::build(
            self.store.clone(),
            &self.origin,
            policy,
            self.observations.clone(),
        )?;
        *self.current.write().await = app;
        self.selected = index;
        Ok(())
    }
    pub async fn disable(&self) -> FixtureResult<()> {
        let reg = self.policies[self.selected]
            .as_ref()
            .ok_or("missing source")?
            .registration();
        Ok(self
            .store
            .disable_saml_registration(reg.realm(), reg.connection(), reg.client())
            .await?)
    }
    pub async fn facts(&self) -> FixtureResult<serde_json::Value> {
        let row:(i64,i64,i64,i64,i64,i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_saml_identities),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit),(SELECT count(*) FROM auth_saml_requests),(SELECT count(*) FROM auth_saml_replays),(SELECT count(DISTINCT realm_id) FROM auth_saml_identities),(SELECT count(DISTINCT subject) FROM auth_saml_identities)")
            .fetch_one(&self.pool).await?;
        Ok(
            serde_json::json!({"users":row.0,"identities":row.1,"sessions":row.2,"audit":row.3,"pending":row.4,"replays":row.5,"identity_realms":row.6,"subjects":row.7,"timing":self.observations.facts(&self.pool).await?}),
        )
    }
    pub async fn close(self) -> FixtureResult<()> {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(5), self.server).await???;
        Ok(())
    }
}
