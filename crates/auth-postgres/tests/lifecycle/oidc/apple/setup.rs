use super::provider::{CLIENT, ISSUER, Provider};
use crate::support::realm;
use auth_core::*;
use easy_auth_postgres::Postgres;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub(super) struct Attempt {
    pub start: AppleAuthorizationStart,
    pub browser: Secret,
    pub code: Secret,
}
impl Attempt {
    pub fn intent(&self) -> OAuthIntent<'_> {
        OAuthIntent {
            browser: &self.browser,
            source: "owned-apple-postgres",
            purpose: OAuthPurpose::SignIn,
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
    pub fn response(&self, error: Option<&str>) -> AppleAuthorizationResponse {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("state", self.start.transaction.state.expose());
        if let Some(error) = error {
            form.append_pair("error", error);
        } else {
            form.append_pair("code", self.code.expose());
        }
        AppleAuthorizationResponse::parse(&form.finish()).unwrap()
    }
}
pub(super) struct Fixture {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub policy: OidcIdentityPolicy,
    pub provider: Arc<Provider>,
    pub flow: Arc<AppleAuthorization>,
    pub kind: AppleClientType,
}
impl Fixture {
    pub async fn new(pool: PgPool, kind: AppleClientType, jit: OidcJitPolicy) -> Self {
        let (store, realm) = realm(pool.clone()).await;
        let store = Arc::new(store);
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&pool)
                .await
                .unwrap();
        let (provider, signer) = Provider::new(now as u64);
        let client = Uuid::new_v4();
        let c = OAuthConnection::new(
            realm,
            Uuid::new_v4(),
            client,
            ISSUER,
            CLIENT,
            &format!("https://app.example/apple/{realm}/{client}"),
            OAuthMixupDefense::DedicatedRedirect,
        )
        .unwrap();
        let policy = OidcIdentityPolicy::new(c, &[ISSUER], OidcDisplayNameClaim::Subject)
            .unwrap()
            .with_jit(jit);
        let policy = store.configure_oidc_identity_policy(&policy).await.unwrap();
        let component = Arc::new(
            AppleCodeExchange::new(
                policy.configuration().clone(),
                store.clone(),
                store.clone(),
                signer,
                kind,
                provider.clone(),
                provider.clone(),
            )
            .unwrap(),
        );
        let flow = Arc::new(
            AppleAuthorization::new(
                Arc::new(OAuthTransactions::new(
                    policy.configuration().clone(),
                    store.clone(),
                )),
                component,
            )
            .unwrap(),
        );
        Self {
            pool,
            store,
            policy,
            provider,
            flow,
            kind,
        }
    }
    pub fn realm(&self) -> Uuid {
        self.policy.configuration().realm()
    }
    pub async fn prepare(&self, subject: &str, attributes: Value) -> Attempt {
        let browser = Secret::generate().unwrap();
        let code = Secret::generate().unwrap();
        let start = self
            .flow
            .begin(&OAuthIntent {
                browser: &browser,
                source: "owned-apple-postgres",
                purpose: OAuthPurpose::SignIn,
            })
            .await
            .unwrap();
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&self.pool)
                .await
                .unwrap();
        let mut claims = json!({"iss":ISSUER,"sub":subject,"aud":CLIENT,"iat":now,"exp":now+120,"nonce":start.request.nonce()});
        for (key, value) in attributes.as_object().unwrap() {
            claims[key] = value.clone();
        }
        self.provider.issue(
            &code,
            claims,
            (self.kind == AppleClientType::Web).then_some(self.policy.configuration().redirect()),
        );
        Attempt {
            start,
            browser,
            code,
        }
    }
    pub async fn finish(&self, a: &Attempt) -> Result<VerifiedOidcIdentity> {
        let result = self
            .flow
            .finish(
                &a.intent(),
                &a.start.transaction.state,
                a.proof(),
                self.policy.configuration().redirect(),
                a.response(None),
            )
            .await?;
        match result {
            AppleAuthorizationCompletion::Verified { identity, .. } => Ok(*identity),
            _ => panic!("owned positive must not be a denial"),
        }
    }
    pub async fn signin(&self, a: &Attempt) -> Result<(User, Secret)> {
        let identity = self.finish(a).await?;
        OidcSignIn::new(self.store.clone())
            .finish(self.policy.map(identity)?)
            .await
    }
    pub async fn facts(&self) -> (i64, i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1),(SELECT count(*) FROM auth_oauth_transactions WHERE realm_id=$1)")
            .bind(self.realm()).fetch_one(&self.pool).await.unwrap()
    }
}
