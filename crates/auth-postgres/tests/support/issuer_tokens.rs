use auth_core::{IssuerAuthority, IssuerKeyPublication, IssuerSigningKey};
use auth_core::{
    IssuerAuthorization, IssuerAuthorizationInput, IssuerClientAuthentication,
    IssuerClientRegistration, IssuerPkceVerifier, IssuerTokenIssuer, IssuerTokenRepository,
    Repository, Secret,
};
use easy_auth_postgres::Postgres;
use josekit::{jwk::KeyPair, jws::RS256};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct Tokens {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub authority: IssuerAuthority,
    pub key: Arc<IssuerSigningKey>,
    pub client: IssuerClientRegistration,
    pub current: Secret,
    pub browser: Secret,
    pub pkce: IssuerPkceVerifier,
    pub owner: Uuid,
    pub authorization: IssuerAuthorization,
}
impl Tokens {
    pub async fn new(pool: PgPool) -> Self {
        let (store, realm) = crate::support::realm(pool.clone()).await;
        let current = crate::support::signed_in(&store, realm, "owner@example.test").await;
        let owner = store
            .authenticate(realm, current.verifier())
            .await
            .unwrap()
            .id;
        let authority = IssuerAuthority::new(realm, "https://issuer.example").unwrap();
        let pair = RS256.generate_key_pair(2048).unwrap();
        let key = Arc::new(
            IssuerSigningKey::from_pkcs8_pem(
                Uuid::new_v4(),
                String::from_utf8(pair.to_pem_private_key()).unwrap(),
            )
            .unwrap(),
        );
        let now: i64 =
            sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
                .fetch_one(&pool)
                .await
                .unwrap();
        let publication = IssuerKeyPublication::new(
            authority.clone(),
            key.public_key().unwrap(),
            now - 1_000_000,
            now + 3_600_000_000,
            now + 3_900_000_000,
        )
        .unwrap();
        store.publish_issuer_key(&publication).await.unwrap();
        let revision = store
            .activate_issuer_key(&authority, key.id())
            .await
            .unwrap();
        store
            .enable_issuer_signing(&authority, revision)
            .await
            .unwrap();
        let client = store
            .configure_issuer_client(
                &IssuerClientRegistration::public(
                    realm,
                    Uuid::new_v4(),
                    &["https://app.example/cb"],
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let store = Arc::new(store);
        Self {
            authorization: IssuerAuthorization::new(authority.clone(), store.clone()),
            pool,
            store,
            authority,
            key,
            client,
            current,
            browser: Secret::generate().unwrap(),
            pkce: IssuerPkceVerifier::parse(Secret::generate().unwrap().expose().to_owned())
                .unwrap(),
            owner,
        }
    }
    pub fn service(&self) -> IssuerTokenIssuer {
        self.with_repository(self.store.clone())
    }
    pub fn with_repository(&self, repository: Arc<dyn IssuerTokenRepository>) -> IssuerTokenIssuer {
        IssuerTokenIssuer::new(self.authority.clone(), repository, vec![self.key.clone()]).unwrap()
    }
    pub fn authentication(&self) -> IssuerClientAuthentication {
        IssuerClientAuthentication::public(self.client.client()).unwrap()
    }
    pub async fn code(&self) -> Secret {
        let pending = self
            .authorization
            .prepare(
                &self.current,
                &self.browser,
                &IssuerAuthorizationInput {
                    client: self.client.client(),
                    response_type: "code",
                    redirect_uri: "https://app.example/cb",
                    scope: "openid",
                    state: "client-state",
                    nonce: "client-nonce",
                    code_challenge: &self.pkce.challenge(),
                    code_challenge_method: "S256",
                },
            )
            .await
            .unwrap();
        let returned = self
            .authorization
            .approve(
                &self.current,
                &self.browser,
                pending.handle(),
                pending.authorization(),
            )
            .await
            .unwrap();
        let url = url::Url::parse(returned.url()).unwrap();
        Secret::parse(
            url.query_pairs()
                .find(|(k, _)| k == "code")
                .unwrap()
                .1
                .into_owned(),
        )
        .unwrap()
    }
    pub async fn facts(&self) -> (i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_access_tokens WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='issuer_code_redeemed')")
            .bind(self.authority.realm()).fetch_one(&self.pool).await.unwrap()
    }
}
