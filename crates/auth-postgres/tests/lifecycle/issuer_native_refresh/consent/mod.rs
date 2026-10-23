mod bindings;
mod isolation;
mod lifecycle;
mod ordering;
mod storage;
mod upgrade;

use auth_core::{
    Error, IssuerAuthorization, IssuerAuthorizationInput, IssuerNativeAuthorization,
    IssuerNativeAuthorizationInput, IssuerNativeAuthorizationStart, IssuerNativeRefreshPolicy,
    IssuerPkceVerifier, Repository, Secret,
};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

struct Fixture {
    pool: PgPool,
    store: Arc<Postgres>,
    policy: IssuerNativeRefreshPolicy,
    current: Secret,
    browser: Secret,
    pkce: IssuerPkceVerifier,
    service: Arc<IssuerNativeAuthorization>,
    owner: Uuid,
}
impl Fixture {
    async fn new(pool: PgPool) -> Self {
        let (store, input) = super::setup(&pool).await;
        let policy = store
            .configure_issuer_native_refresh_policy(&input)
            .await
            .unwrap();
        store
            .enable_issuer_native_refresh_policy(&policy)
            .await
            .unwrap();
        let current =
            crate::support::signed_in(&store, policy.authority().realm(), "owner@example.test")
                .await;
        let owner = store
            .authenticate(policy.authority().realm(), current.verifier())
            .await
            .unwrap()
            .id;
        let store = Arc::new(store);
        Self {
            service: Arc::new(IssuerNativeAuthorization::new(
                policy.authority().clone(),
                store.clone(),
            )),
            pool,
            store,
            policy,
            current,
            browser: Secret::generate().unwrap(),
            pkce: IssuerPkceVerifier::parse(Secret::generate().unwrap().expose().to_owned())
                .unwrap(),
            owner,
        }
    }
    async fn prepare(&self) -> IssuerNativeAuthorizationStart {
        self.prepare_with("openid offline_access", "consent")
            .await
            .unwrap()
    }
    async fn prepare_with(
        &self,
        scope: &str,
        prompt: &str,
    ) -> auth_core::Result<IssuerNativeAuthorizationStart> {
        self.service
            .prepare(
                &self.current,
                &self.browser,
                &IssuerNativeAuthorizationInput {
                    authorization: IssuerAuthorizationInput {
                        client: self.policy.client().client(),
                        response_type: "code",
                        redirect_uri: "http://127.0.0.1:41002/cb",
                        scope,
                        state: "owned-state",
                        nonce: "owned-nonce",
                        code_challenge: &self.pkce.challenge(),
                        code_challenge_method: "S256",
                    },
                    prompt,
                },
            )
            .await
    }
    fn online(&self) -> IssuerAuthorization {
        IssuerAuthorization::new(self.policy.authority().clone(), self.store.clone())
    }
    async fn facts(&self) -> (i64, i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_issuer_authorizations WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_native_consents WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_subjects WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_access_tokens WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='issuer_authorized')")
            .bind(self.policy.authority().realm()).fetch_one(&self.pool).await.unwrap()
    }
}
