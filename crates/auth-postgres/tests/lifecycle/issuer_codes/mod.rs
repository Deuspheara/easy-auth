mod binding;
mod lifecycle;

use auth_core::{
    IssuerAuthority, IssuerAuthorization, IssuerAuthorizationInput, IssuerAuthorizationStart,
    IssuerClientAuthentication, IssuerClientRegistration, IssuerPkceVerifier, Repository, Secret,
};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

struct Fixture {
    store: Arc<Postgres>,
    service: IssuerAuthorization,
    realm: Uuid,
    owner: Uuid,
    current: Secret,
    browser: Secret,
    client: IssuerClientRegistration,
    pkce: IssuerPkceVerifier,
    redirect: String,
}
impl Fixture {
    async fn new(pool: &PgPool, native: bool) -> Self {
        let (store, realm) = crate::support::realm(pool.clone()).await;
        let current = crate::support::signed_in(&store, realm, "owner@example.test").await;
        let owner = store
            .authenticate(realm, current.verifier())
            .await
            .unwrap()
            .id;
        let redirect = if native {
            "http://127.0.0.1:49152/callback"
        } else {
            "https://app.example/cb?fixed=%2f"
        }
        .to_owned();
        let registration = if native {
            IssuerClientRegistration::public_native_loopback(realm, Uuid::new_v4(), &[&redirect])
        } else {
            IssuerClientRegistration::public(realm, Uuid::new_v4(), &[&redirect])
        }
        .unwrap();
        let client = store.configure_issuer_client(&registration).await.unwrap();
        let store = Arc::new(store);
        let service = IssuerAuthorization::new(
            IssuerAuthority::new(realm, "https://issuer.example").unwrap(),
            store.clone(),
        );
        Self {
            store,
            service,
            realm,
            owner,
            current,
            browser: Secret::generate().unwrap(),
            client,
            pkce: IssuerPkceVerifier::parse(Secret::generate().unwrap().expose().to_owned())
                .unwrap(),
            redirect,
        }
    }
    async fn prepare(&self) -> auth_core::Result<IssuerAuthorizationStart> {
        self.service
            .prepare(
                &self.current,
                &self.browser,
                &IssuerAuthorizationInput {
                    client: self.client.client(),
                    response_type: "code",
                    redirect_uri: &self.redirect,
                    scope: "openid",
                    state: "client-state",
                    nonce: "client-nonce",
                    code_challenge: &self.pkce.challenge(),
                    code_challenge_method: "S256",
                },
            )
            .await
    }
    fn authentication(&self) -> IssuerClientAuthentication {
        IssuerClientAuthentication::public(self.client.client()).unwrap()
    }
    async fn approve(&self, pending: &IssuerAuthorizationStart) -> Secret {
        let response = self
            .service
            .approve(
                &self.current,
                &self.browser,
                pending.handle(),
                pending.authorization(),
            )
            .await
            .unwrap();
        let parsed = url::Url::parse(response.url()).unwrap();
        assert!(response.url().starts_with(&self.redirect));
        assert!(
            parsed
                .query_pairs()
                .any(|(k, v)| k == "state" && v == "client-state")
        );
        assert!(
            parsed
                .query_pairs()
                .any(|(k, v)| k == "iss" && v == "https://issuer.example")
        );
        let code = parsed
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        Secret::parse(code).unwrap()
    }
    async fn count(&self, pool: &PgPool, table: &str) -> i64 {
        // Only static test table names reach this private fixture.
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE realm_id=$1"))
            .bind(self.realm)
            .fetch_one(pool)
            .await
            .unwrap()
    }
}

mod admission;
mod credentials;
mod ordering;
mod rollback;
mod upgrade;

mod deadlines;

mod storage;
