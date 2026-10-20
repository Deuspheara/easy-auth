use crate::support::realm;
use async_trait::async_trait;
use auth_core::*;
use easy_auth_postgres::Postgres;
use josekit::{
    jwk::KeyPair,
    jws::{self, ES256, JwsHeader, JwsSigner},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use uuid::Uuid;

struct Http {
    public: Value,
    issuer: String,
}
#[async_trait]
impl OidcHttp for Http {
    async fn resolve(&self, _: &str, port: u16) -> Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::from(([8, 8, 8, 8], port))])
    }
    async fn get(&self, target: &OidcTarget) -> Result<OidcHttpResponse> {
        let value = if target.url().path().ends_with("openid-configuration") {
            json!({"issuer":self.issuer,"authorization_endpoint":format!("{}/authorize",self.issuer),"token_endpoint":format!("{}/token",self.issuer),"jwks_uri":format!("{}/keys",self.issuer),"authorization_response_iss_parameter_supported":true})
        } else {
            json!({"keys":[self.public]})
        };
        Ok(OidcHttpResponse {
            status: 200,
            content_type: Some("application/json".into()),
            content_encoding: None,
            body: serde_json::to_vec(&value).unwrap(),
            cache_seconds: 300,
        })
    }
}

pub(super) struct Fixture {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub policy: OidcIdentityPolicy,
    pub sign_in: OidcSignIn,
    verifier: OidcTokenVerifier,
    http: Arc<Http>,
    signer: Box<dyn JwsSigner>,
}

impl Fixture {
    pub async fn new(pool: PgPool, jit: OidcJitPolicy) -> Self {
        let (store, realm) = realm(pool.clone()).await;
        let id = Uuid::new_v4();
        Self::scoped(pool, Arc::new(store), realm, id, Uuid::new_v4(), jit).await
    }
    pub async fn scoped(
        pool: PgPool,
        store: Arc<Postgres>,
        realm: Uuid,
        id: Uuid,
        client: Uuid,
        jit: OidcJitPolicy,
    ) -> Self {
        store.ensure_realm(realm).await.unwrap();
        let connection = OAuthConnection::new(
            realm,
            id,
            client,
            "https://issuer.example",
            "client",
            &format!("https://app.example/callback/{realm}/{id}/{client}"),
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        let policy = OidcIdentityPolicy::new(
            connection,
            &["https://issuer.example"],
            OidcDisplayNameClaim::Name,
        )
        .unwrap()
        .with_jit(jit);
        Self::configured(pool, store, policy).await
    }
    pub async fn configured(
        pool: PgPool,
        store: Arc<Postgres>,
        policy: OidcIdentityPolicy,
    ) -> Self {
        store
            .ensure_realm(policy.configuration().realm())
            .await
            .unwrap();
        let policy = store.configure_oidc_identity_policy(&policy).await.unwrap();
        let key = ES256.generate_key_pair().unwrap();
        let mut public = key.to_jwk_public_key();
        public.set_key_id("owned");
        public.set_algorithm("ES256");
        public.set_key_use("sig");
        let http = Arc::new(Http {
            public: serde_json::to_value(public).unwrap(),
            issuer: policy.configuration().issuer().to_owned(),
        });
        let verifier = verifier(&policy, store.clone(), http.clone());
        Self {
            pool,
            sign_in: OidcSignIn::new(store.clone()),
            store,
            policy,
            verifier,
            http,
            signer: Box::new(ES256.signer_from_der(key.to_der_private_key()).unwrap()),
        }
    }
    pub fn realm(&self) -> Uuid {
        self.policy.configuration().realm()
    }
    pub async fn reconfigure(&mut self, jit: OidcJitPolicy) {
        self.policy = self
            .store
            .configure_oidc_identity_policy(&self.policy.clone().with_jit(jit))
            .await
            .unwrap();
        self.verifier = verifier(&self.policy, self.store.clone(), self.http.clone());
    }
    pub async fn now_seconds(&self) -> i64 {
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    pub async fn mapped(&self, subject: &str, attributes: Value) -> OidcMappedIdentity {
        self.mapped_for(subject, attributes, OAuthPurpose::SignIn, None)
            .await
    }
    pub async fn mapped_for(
        &self,
        subject: &str,
        attributes: Value,
        purpose: OAuthPurpose,
        cap_seconds: Option<i32>,
    ) -> OidcMappedIdentity {
        self.try_mapped_for(subject, attributes, purpose, cap_seconds)
            .await
            .unwrap()
    }
    pub async fn try_mapped_for(
        &self,
        subject: &str,
        attributes: Value,
        purpose: OAuthPurpose,
        cap_seconds: Option<i32>,
    ) -> Result<OidcMappedIdentity> {
        let c = self.policy.configuration();
        let flow = OAuthTransactions::new(c.clone(), self.store.clone());
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "signed-oidc-owned-test",
            purpose,
        };
        let start = flow.begin(&intent).await.unwrap();
        if let Some(cap) = cap_seconds {
            sqlx::query("UPDATE auth_oauth_transactions SET expires_at=clock_timestamp()+$3*interval '1 second' WHERE realm_id=$1 AND state_hash=$2")
                .bind(c.realm()).bind(start.state.verifier().as_slice()).bind(cap).execute(&self.pool).await.unwrap();
        }
        let now = self.now_seconds().await;
        let mut claims = json!({"iss":c.issuer(),"sub":subject,"aud":c.provider_client(),"iat":now,"exp":now+120,"nonce":start.proof.nonce().expose(),"name":"Provider display"});
        for (key, value) in attributes.as_object().unwrap() {
            claims[key] = value.clone();
        }
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id("owned");
        let raw = jws::serialize_compact(
            &serde_json::to_vec(&claims).unwrap(),
            &header,
            self.signer.as_ref(),
        )
        .unwrap();
        let exchange = flow
            .consume(
                &intent,
                &start.state,
                start.proof,
                OAuthCallback {
                    redirect: c.redirect(),
                    issuer: Some(c.issuer()),
                },
            )
            .await
            .unwrap();
        let verified = self
            .verifier
            .verify(exchange, OidcIdToken::parse(raw).unwrap())
            .await?;
        self.policy.map(verified)
    }
    pub async fn facts(&self) -> (i64, i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_oidc_identities),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit),(SELECT count(*) FROM auth_oauth_transactions)")
            .fetch_one(&self.pool).await.unwrap()
    }
    pub async fn wait_for_expiry(&self, cap: i64) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let expired: bool = sqlx::query_scalar(
                    "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint >= $1",
                )
                .bind(cap)
                .fetch_one(&self.pool)
                .await
                .expect("test infrastructure: observe original proof clock");
                if expired {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("test infrastructure: original proof did not expire");
    }
}

fn verifier(
    policy: &OidcIdentityPolicy,
    store: Arc<Postgres>,
    http: Arc<Http>,
) -> OidcTokenVerifier {
    let origin = url::Url::parse(policy.configuration().issuer())
        .unwrap()
        .origin()
        .ascii_serialization();
    let documents = Arc::new(
        OidcDocuments::new(
            policy.configuration().clone(),
            &[&origin],
            store.clone(),
            http,
        )
        .unwrap(),
    );
    OidcTokenVerifier::new(
        documents,
        store,
        OidcVerificationPolicy::new(&[OidcSigningAlgorithm::ES256], &[]).unwrap(),
    )
}

pub(super) async fn wait_for_lock(pool: &PgPool, pattern: &str) {
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: independent identity observer");
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)").bind(pattern).fetch_one(&observer).await.expect("test infrastructure: observe identity lock");
            if waiting { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: identity action did not reach expected lock");
    observer.close().await;
}
