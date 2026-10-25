use super::provider::{CLIENT, ISSUER, Provider};
use crate::support::{realm, signed_in};
pub(super) use auth_core::*;
use easy_auth_postgres::Postgres;
pub(super) use serde_json::{Value, json};
use sqlx::PgPool;
pub(super) use std::sync::{Arc, atomic::Ordering};
use uuid::Uuid;

pub(super) struct Attempt {
    pub start: AppleAuthorizationStart,
    pub browser: Secret,
    pub code: Secret,
    pub purpose: OAuthPurpose,
}
impl Attempt {
    pub fn intent(&self) -> OAuthIntent<'_> {
        OAuthIntent {
            browser: &self.browser,
            source: "owned-social-linking",
            purpose: self.purpose.clone(),
        }
    }
    pub fn proof(&self) -> OAuthBrowserProof {
        OAuthBrowserProof::parse(
            self.start.transaction.proof.nonce().expose().to_owned(),
            self.start
                .transaction
                .proof
                .pkce_verifier()
                .expose()
                .to_owned(),
        )
        .unwrap()
    }
    pub fn response(&self) -> AppleAuthorizationResponse {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("state", self.start.transaction.state.expose())
            .append_pair("code", self.code.expose());
        AppleAuthorizationResponse::parse(&form.finish()).unwrap()
    }
}
pub(super) struct Fixture {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub policy: OidcIdentityPolicy,
    pub provider: Arc<Provider>,
    pub link: AppleIdentityLinkAuthorization,
    pub signin: AppleAuthorization,
    pub linking: OidcIdentityLinking,
}
impl Fixture {
    pub async fn new(pool: PgPool) -> Self {
        Self::with_jit(pool, OidcJitPolicy::Deny).await
    }
    pub async fn with_jit(pool: PgPool, jit: OidcJitPolicy) -> Self {
        let (store, realm) = realm(pool.clone()).await;
        let store = Arc::new(store);
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&pool)
                .await
                .unwrap();
        let (provider, signer) = Provider::new(now as u64);
        let config = OAuthConnection::new(
            realm,
            Uuid::new_v4(),
            Uuid::new_v4(),
            ISSUER,
            CLIENT,
            &format!("https://app.example/apple/link/{realm}"),
            OAuthMixupDefense::DedicatedRedirect,
        )
        .unwrap();
        let policy = store
            .configure_oidc_identity_policy(
                &OidcIdentityPolicy::new(config, &[ISSUER], OidcDisplayNameClaim::Subject)
                    .unwrap()
                    .with_jit(jit),
            )
            .await
            .unwrap();
        let exchange = Arc::new(
            AppleCodeExchange::new(
                policy.configuration().clone(),
                store.clone(),
                store.clone(),
                signer,
                AppleClientType::Web,
                provider.clone(),
                provider.clone(),
            )
            .unwrap(),
        );
        let transactions = Arc::new(OAuthTransactions::new(
            policy.configuration().clone(),
            store.clone(),
        ));
        let link =
            AppleIdentityLinkAuthorization::new(transactions.clone(), exchange.clone()).unwrap();
        let signin = AppleAuthorization::new(transactions, exchange).unwrap();
        let linking = OidcIdentityLinking::new(store.clone());
        Self {
            pool,
            store,
            policy,
            provider,
            link,
            signin,
            linking,
        }
    }
    pub fn realm(&self) -> Uuid {
        self.policy.configuration().realm()
    }
    pub async fn local(&self, email: &str) -> (User, Secret) {
        let session = signed_in(self.store.as_ref(), self.realm(), email).await;
        let user = self
            .store
            .authenticate(self.realm(), session.verifier())
            .await
            .unwrap();
        (user, session)
    }
    pub async fn prepare(
        &self,
        purpose: OAuthPurpose,
        subject: &str,
        attributes: Value,
    ) -> Attempt {
        let browser = Secret::generate().unwrap();
        let code = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-social-linking",
            purpose: purpose.clone(),
        };
        let start = match purpose {
            OAuthPurpose::Link { .. } => self.link.begin(&intent).await,
            OAuthPurpose::SignIn => self.signin.begin(&intent).await,
            _ => panic!("fixture purpose unsupported"),
        }
        .expect("normal core preparation must succeed");
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&self.pool)
                .await
                .unwrap();
        let mut claims = json!({"iss":ISSUER,"aud":CLIENT,"sub":subject,"iat":now,"exp":now+120,"nonce":start.request.nonce()});
        for (key, value) in attributes.as_object().unwrap() {
            claims[key] = value.clone();
        }
        self.provider
            .issue(&code, claims, Some(self.policy.configuration().redirect()));
        Attempt {
            start,
            browser,
            code,
            purpose,
        }
    }
    pub async fn complete(&self, a: &Attempt) -> Result<OidcMappedIdentity> {
        let value = match a.purpose {
            OAuthPurpose::Link { .. } => {
                self.link
                    .finish(
                        &a.intent(),
                        &a.start.transaction.state,
                        a.proof(),
                        self.policy.configuration().redirect(),
                        a.response(),
                    )
                    .await?
            }
            OAuthPurpose::SignIn => {
                self.signin
                    .finish(
                        &a.intent(),
                        &a.start.transaction.state,
                        a.proof(),
                        self.policy.configuration().redirect(),
                        a.response(),
                    )
                    .await?
            }
            _ => panic!("fixture purpose unsupported"),
        };
        match value {
            AppleAuthorizationCompletion::Verified { identity, .. } => self.policy.map(*identity),
            _ => panic!("normal code producer must verify"),
        }
    }
    pub async fn linked(&self, owner: &User, current: &Secret, subject: &str) -> LinkedProvider {
        let a = self
            .prepare(
                OAuthPurpose::Link {
                    user: owner.id,
                    session: current.verifier(),
                },
                subject,
                json!({}),
            )
            .await;
        self.linking
            .finish(self.complete(&a).await.unwrap(), current)
            .await
            .unwrap()
    }
    pub async fn login(&self, subject: &str) -> Result<(User, Secret)> {
        let a = self.prepare(OAuthPurpose::SignIn, subject, json!({})).await;
        OidcSignIn::new(self.store.clone())
            .finish(self.complete(&a).await?)
            .await
    }
    pub async fn facts(&self) -> (i64, i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1),(SELECT count(*) FROM auth_security_notifications WHERE realm_id=$1)").bind(self.realm()).fetch_one(&self.pool).await.unwrap()
    }
}
