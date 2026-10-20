use super::provider::{CLIENT, ISSUER, Provider};
use crate::support::realm;
use auth_core::*;
use easy_auth_postgres::Postgres;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const PENDING_WINDOW_SECONDS: i32 = 300;
const TOKEN_LIFETIME_SECONDS: i64 = 120;

pub(super) struct Attempt {
    pub start: OAuthStart,
    pub browser: Secret,
    pub code: Secret,
    pub cap: i64,
}
impl Attempt {
    pub fn intent(&self) -> OAuthIntent<'_> {
        OAuthIntent {
            browser: &self.browser,
            source: "owned-google-postgres",
            purpose: OAuthPurpose::SignIn,
        }
    }
    pub fn proof(&self) -> OAuthBrowserProof {
        OAuthBrowserProof::parse(
            self.start.proof.nonce().expose().to_owned(),
            self.start.proof.pkce_verifier().expose().to_owned(),
        )
        .unwrap()
    }
    pub fn authorization_code(&self) -> OidcAuthorizationCode {
        OidcAuthorizationCode::parse(self.code.expose().to_owned()).unwrap()
    }
}
pub(super) struct Fixture {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub policy: OidcIdentityPolicy,
    pub google: Arc<GoogleCodeExchange>,
    pub provider: Arc<Provider>,
}
impl Fixture {
    pub async fn new(pool: PgPool, desktop: bool, jit: OidcJitPolicy) -> Self {
        let (store, realm) = realm(pool.clone()).await;
        Self::scoped(pool, Arc::new(store), realm, Provider::new(), desktop, jit).await
    }
    pub async fn scoped(
        pool: PgPool,
        store: Arc<Postgres>,
        realm: Uuid,
        provider: Arc<Provider>,
        desktop: bool,
        jit: OidcJitPolicy,
    ) -> Self {
        store.ensure_realm(realm).await.unwrap();
        let client = Uuid::new_v4();
        let path = format!("/callback/{realm}/{client}");
        let redirect = if desktop {
            OAuthRedirect::desktop_loopback("127.0.0.1:49153".parse().unwrap(), &path).unwrap()
        } else {
            OAuthRedirect::https(&format!("https://app.example{path}")).unwrap()
        };
        let c = OAuthConnection::with_redirect(
            realm,
            Uuid::new_v4(),
            client,
            ISSUER,
            CLIENT,
            redirect,
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        let policy = OidcIdentityPolicy::new(c, &[ISSUER], OidcDisplayNameClaim::Subject)
            .unwrap()
            .with_jit(jit);
        let policy = store.configure_oidc_identity_policy(&policy).await.unwrap();
        let google = Self::client(&policy, &store, &provider);
        Self {
            pool,
            store,
            policy,
            google,
            provider,
        }
    }
    fn client(
        policy: &OidcIdentityPolicy,
        store: &Arc<Postgres>,
        provider: &Arc<Provider>,
    ) -> Arc<GoogleCodeExchange> {
        Arc::new(
            GoogleCodeExchange::new(
                policy.configuration().clone(),
                store.clone(),
                store.clone(),
                provider.authentication(),
                provider.clone(),
                provider.clone(),
            )
            .unwrap(),
        )
    }
    pub fn realm(&self) -> Uuid {
        self.policy.configuration().realm()
    }
    pub fn flow(&self) -> OAuthTransactions {
        OAuthTransactions::new(self.policy.configuration().clone(), self.store.clone())
    }
    pub async fn reconfigure(&mut self, jit: OidcJitPolicy) {
        self.policy = self
            .store
            .configure_oidc_identity_policy(&self.policy.clone().with_jit(jit))
            .await
            .unwrap();
        self.google = Self::client(&self.policy, &self.store, &self.provider);
    }
    pub async fn prepare(&self, subject: &str, attributes: Value, cap: Option<i32>) -> Attempt {
        let browser = Secret::generate().unwrap();
        let code = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-google-postgres",
            purpose: OAuthPurpose::SignIn,
        };
        let start = self.flow().begin(&intent).await.unwrap();
        if let Some(cap) = cap {
            assert!((1..=PENDING_WINDOW_SECONDS).contains(&cap));
            let rows=sqlx::query("UPDATE auth_oauth_transactions SET created_at=statement_timestamp()-($4::int-$3::int)*interval '1 second',expires_at=statement_timestamp()+$3::int*interval '1 second' WHERE realm_id=$1 AND state_hash=$2")
                .bind(self.realm()).bind(start.state.verifier().as_slice()).bind(cap).bind(PENDING_WINDOW_SECONDS).execute(&self.pool).await.unwrap().rows_affected();
            assert_eq!(rows, 1, "one owned pending deadline arranged");
        }
        let (cap,original_window):(i64,bool)=sqlx::query_as("SELECT (extract(epoch FROM expires_at)*1000000)::bigint,expires_at-created_at=$3::int*interval '1 second' FROM auth_oauth_transactions WHERE realm_id=$1 AND state_hash=$2")
            .bind(self.realm()).bind(start.state.verifier().as_slice()).bind(PENDING_WINDOW_SECONDS).fetch_one(&self.pool).await.unwrap();
        assert!(
            original_window,
            "test infrastructure: original five-minute preparation window preserved"
        );
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&self.pool)
                .await
                .unwrap();
        let mut claims = json!({"iss":ISSUER,"sub":subject,"aud":CLIENT,"iat":now,"exp":now+TOKEN_LIFETIME_SECONDS,"nonce":start.proof.nonce().expose()});
        for (key, value) in attributes.as_object().unwrap() {
            claims[key] = value.clone();
        }
        self.provider
            .issue(&code, &start, self.policy.configuration(), claims);
        Attempt {
            start,
            browser,
            code,
            cap,
        }
    }
    pub async fn consume(&self, a: &Attempt) -> Result<OAuthExchange> {
        self.flow()
            .consume(
                &a.intent(),
                &a.start.state,
                a.proof(),
                OAuthCallback {
                    redirect: self.policy.configuration().redirect(),
                    issuer: Some(ISSUER),
                },
            )
            .await
    }
    pub async fn verified(&self, a: &Attempt) -> Result<VerifiedOidcIdentity> {
        self.google
            .exchange(self.consume(a).await?, a.authorization_code())
            .await
    }
    pub async fn mapped(&self, subject: &str, attributes: Value) -> OidcMappedIdentity {
        let a = self.prepare(subject, attributes, None).await;
        self.policy.map(self.verified(&a).await.unwrap()).unwrap()
    }
    pub async fn sign_in(&self, mapped: OidcMappedIdentity) -> Result<(User, Secret)> {
        OidcSignIn::new(self.store.clone()).finish(mapped).await
    }
    pub async fn facts(&self) -> (i64, i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1),(SELECT count(*) FROM auth_oauth_transactions WHERE realm_id=$1)")
            .bind(self.realm()).fetch_one(&self.pool).await.expect("test infrastructure: scoped Google facts")
    }
}
