use crate::support::realm;
use auth_core::{
    OAuthBrowserProof, OAuthConnection, OAuthIntent, OAuthMixupDefense, OAuthPurpose, OAuthRequest,
    OAuthStart, OAuthTransactions, Secret,
};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub(super) struct Fixture {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub connection: OAuthConnection,
    pub flow: OAuthTransactions,
    pub browser: Secret,
}

impl Fixture {
    pub async fn new(pool: PgPool) -> Self {
        let (store, realm) = realm(pool.clone()).await;
        let connection = connection(realm, Uuid::new_v4(), Uuid::new_v4());
        let connection = store.configure_oauth_connection(&connection).await.unwrap();
        let store = Arc::new(store);
        let flow = OAuthTransactions::new(connection.clone(), store.clone());
        Self {
            pool,
            store,
            connection,
            flow,
            browser: Secret::generate().unwrap(),
        }
    }
    pub fn intent(&self, purpose: OAuthPurpose) -> OAuthIntent<'_> {
        OAuthIntent {
            browser: &self.browser,
            source: "192.0.2.22",
            purpose,
        }
    }
    pub async fn start(&self) -> OAuthStart {
        self.flow
            .begin(&self.intent(OAuthPurpose::SignIn))
            .await
            .unwrap()
    }
    pub fn request(&self, start: &OAuthStart, purpose: OAuthPurpose) -> OAuthRequest {
        OAuthRequest {
            configuration: self.connection.clone(),
            purpose,
            browser: self.browser.verifier(),
            source: [22; 32],
            state: start.state.verifier(),
            nonce: start.proof.nonce().verifier(),
            pkce: start.proof.pkce_verifier().verifier(),
        }
    }
    pub async fn pending(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM auth_oauth_transactions")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

pub(super) fn connection(realm: Uuid, id: Uuid, client: Uuid) -> OAuthConnection {
    OAuthConnection::new(
        realm,
        id,
        client,
        "https://issuer.example",
        "provider-client",
        &format!("https://app.example/callback/{id}/{client}"),
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap()
}

pub(super) fn copy_proof(proof: &OAuthBrowserProof) -> OAuthBrowserProof {
    // Test retries deliberately copy transient proof; never print or persist it.
    OAuthBrowserProof::parse(
        proof.nonce().expose().to_owned(),
        proof.pkce_verifier().expose().to_owned(),
    )
    .unwrap()
}

pub(super) async fn wait_for_sql(pool: &PgPool, pattern: &str) {
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: independent OAuth lock observer");
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)")
                .bind(pattern).fetch_one(&observer).await.expect("test infrastructure: observe OAuth SQL lock");
            if waiting { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: OAuth action did not reach expected SQL lock");
    observer.close().await;
}
