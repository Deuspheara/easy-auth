use super::{
    super::GoogleDesktopSignIn,
    provider::{CLIENT, ISSUER, Provider},
};
use crate::GoogleDesktopListener;
use auth_core::*;
use auth_postgres::Postgres;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{net::IpAddr, sync::Arc};
use uuid::Uuid;

pub(super) const SOURCE: &str = "owned-desktop-launch";
const PENDING_WINDOW_SECONDS: i32 = 300;
const TOKEN_LIFETIME_SECONDS: i64 = 120;

pub(super) struct Fixture {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub policy: OidcIdentityPolicy,
    pub service: Arc<GoogleAuthorization>,
    pub provider: Arc<Provider>,
    pub listener: Option<GoogleDesktopListener>,
    ip: IpAddr,
}
impl Fixture {
    pub async fn new(pool: PgPool, ip: IpAddr) -> Self {
        let store = Arc::new(Postgres::new(pool.clone()));
        let realm = Uuid::new_v4();
        store.ensure_realm(realm).await.unwrap();
        let listener =
            GoogleDesktopListener::bind(ip, &format!("/owned/return/{}", Uuid::new_v4()))
                .await
                .unwrap();
        let config = OAuthConnection::with_redirect(
            realm,
            Uuid::new_v4(),
            Uuid::new_v4(),
            ISSUER,
            CLIENT,
            listener.redirect().clone(),
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        let policy = store
            .configure_oidc_identity_policy(&policy(config))
            .await
            .unwrap();
        let provider = Provider::new();
        let service = service(&policy, &store, &provider);
        Self {
            pool,
            store,
            policy,
            service,
            provider,
            listener: Some(listener),
            ip,
        }
    }
    pub async fn begin(&mut self) -> GoogleDesktopSignIn {
        GoogleDesktopSignIn::begin(self.listener.take().unwrap(), self.service.clone(), SOURCE)
            .await
            .unwrap()
    }
    pub fn uri(&self) -> url::Url {
        url::Url::parse(self.policy.configuration().redirect()).unwrap()
    }
    pub async fn rebind(&mut self) {
        let listener = GoogleDesktopListener::bind(self.ip, self.uri().path())
            .await
            .unwrap();
        let old = self.policy.configuration();
        let config = OAuthConnection::with_redirect(
            old.realm(),
            old.connection(),
            old.client(),
            ISSUER,
            CLIENT,
            listener.redirect().clone(),
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        self.policy = self
            .store
            .configure_oidc_identity_policy(&policy(config))
            .await
            .unwrap();
        self.service = service(&self.policy, &self.store, &self.provider);
        self.listener = Some(listener);
    }
    pub async fn issue(&self, attempt: &GoogleDesktopSignIn, attributes: Value) -> Secret {
        let url = url::Url::parse(attempt.start.authorization_url.expose()).unwrap();
        let field = |name: &str| {
            let values: Vec<_> = url
                .query_pairs()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
                .collect();
            assert_eq!(values.len(), 1, "one original public authorization field");
            values[0].clone()
        };
        assert_eq!(field("client_id"), CLIENT);
        assert!(field("redirect_uri") == self.policy.configuration().redirect());
        assert_eq!(field("code_challenge_method"), "S256");
        let challenge: Verifier = URL_SAFE_NO_PAD
            .decode(field("code_challenge"))
            .unwrap()
            .try_into()
            .unwrap();
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&self.pool)
                .await
                .expect("test infrastructure: native process real clock");
        let mut claims = json!({"iss":ISSUER,"aud":CLIENT,"sub":"owned-native-process","nonce":field("nonce"),"iat":now,"exp":now+TOKEN_LIFETIME_SECONDS});
        for (name, value) in attributes.as_object().unwrap() {
            claims[name] = value.clone();
        }
        let code = Secret::generate().unwrap();
        self.provider
            .issue(&code, challenge, self.policy.configuration(), claims);
        code
    }
    pub async fn cap(&self, attempt: &mut GoogleDesktopSignIn, seconds: i32) {
        assert!((1..=PENDING_WINDOW_SECONDS).contains(&seconds));
        // One clock sample preserves the schema's original five-minute window.
        let expires: i64 = sqlx::query_scalar(
            r#"
            WITH clock AS (SELECT clock_timestamp() AS now)
            UPDATE auth_oauth_transactions
            SET created_at=clock.now-($4::int-$3::int)*interval '1 second',
                expires_at=clock.now+$3::int*interval '1 second'
            FROM clock WHERE realm_id=$1 AND state_hash=$2
            RETURNING (extract(epoch FROM expires_at)*1000000)::bigint
        "#,
        )
        .bind(self.policy.configuration().realm())
        .bind(attempt.start.transaction.state.verifier().as_slice())
        .bind(seconds)
        .bind(PENDING_WINDOW_SECONDS)
        .fetch_one(&self.pool)
        .await
        .unwrap_or_else(|error| {
            let category = if error
                .as_database_error()
                .and_then(|value| value.code())
                .as_deref()
                == Some("23514")
            {
                "deadline_constraint"
            } else {
                "storage"
            };
            panic!("test infrastructure: original native deadline arrangement failed ({category})")
        });
        attempt.start.transaction.expires_us = expires;
    }
    pub async fn facts(&self) -> (i64, i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1),(SELECT count(*) FROM auth_oauth_transactions WHERE realm_id=$1)")
            .bind(self.policy.configuration().realm()).fetch_one(&self.pool).await.expect("test infrastructure: native process scoped authority facts")
    }
    pub async fn commit(&self, completion: GoogleAuthorizationCompletion) -> (User, Secret) {
        let GoogleAuthorizationCompletion::Verified(identity) = completion else {
            panic!("owned process signed positive control required");
        };
        assert!(
            identity.authenticated_at().is_none(),
            "no inferred native freshness"
        );
        let (owner, session) = OidcSignIn::new(self.store.clone())
            .finish(self.policy.map(*identity).unwrap())
            .await
            .unwrap();
        assert!(owner.email.is_none());
        assert_eq!(
            owner.authentication_policy,
            AuthenticationPolicy::ProviderRequired
        );
        assert_eq!(
            self.store
                .authenticate(owner.realm_id, session.verifier())
                .await
                .unwrap(),
            owner
        );
        (owner, session)
    }
}
fn policy(config: OAuthConnection) -> OidcIdentityPolicy {
    OidcIdentityPolicy::new(config, &[ISSUER], OidcDisplayNameClaim::Subject)
        .unwrap()
        .with_jit(OidcJitPolicy::Allow)
}
fn service(
    policy: &OidcIdentityPolicy,
    store: &Arc<Postgres>,
    provider: &Arc<Provider>,
) -> Arc<GoogleAuthorization> {
    let flow = Arc::new(OAuthTransactions::new(
        policy.configuration().clone(),
        store.clone(),
    ));
    let exchange = Arc::new(
        GoogleCodeExchange::new(
            policy.configuration().clone(),
            store.clone(),
            store.clone(),
            provider.authentication(),
            provider.clone(),
            provider.clone(),
        )
        .unwrap(),
    );
    Arc::new(GoogleAuthorization::new(flow, exchange).unwrap())
}
