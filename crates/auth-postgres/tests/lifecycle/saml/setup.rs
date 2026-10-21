use auth_core::{SamlRegistration, SamlTransactions};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub(super) fn registration(realm: Uuid, connection: Uuid, client: Uuid) -> SamlRegistration {
    SamlRegistration::unsigned_redirect(
        realm,
        connection,
        client,
        "urn:example:sp",
        "urn:example:idp",
        "https://idp.example/sso",
        "https://app.example/saml/acs",
    )
    .unwrap()
}

pub(super) struct Fixture {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub registration: SamlRegistration,
    pub flow: SamlTransactions,
}

impl Fixture {
    pub async fn new(pool: PgPool) -> Self {
        let (store, realm) = crate::support::realm(pool.clone()).await;
        let store = Arc::new(store);
        let registration = store
            .configure_saml_registration(&registration(realm, Uuid::new_v4(), Uuid::new_v4()))
            .await
            .unwrap();
        let flow = SamlTransactions::new(registration.clone(), store.clone());
        Self {
            pool,
            store,
            registration,
            flow,
        }
    }

    pub async fn pending(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM auth_saml_requests WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3")
            .bind(self.registration.realm()).bind(self.registration.connection()).bind(self.registration.client())
            .fetch_one(&self.pool).await.unwrap()
    }
}
