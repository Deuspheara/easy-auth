use super::{
    attempt::{Attempt, REQUEST_SOURCE},
    provider::{CLIENT, ISSUER, Provider},
};
use auth_core::*;
use auth_postgres::Postgres;
use easy_auth_server::GoogleDesktopListener;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{net::IpAddr, sync::Arc};
use uuid::Uuid;

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
        let realm = Uuid::new_v4();
        let store = Arc::new(Postgres::new(pool.clone()));
        store.ensure_realm(realm).await.unwrap();
        let client = Uuid::new_v4();
        let listener = GoogleDesktopListener::bind(ip, &format!("/return/{realm}/{client}"))
            .await
            .unwrap();
        let connection = OAuthConnection::with_redirect(
            realm,
            Uuid::new_v4(),
            client,
            ISSUER,
            CLIENT,
            listener.redirect().clone(),
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        let policy = store
            .configure_oidc_identity_policy(&policy(connection))
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
    pub fn realm(&self) -> Uuid {
        self.policy.configuration().realm()
    }
    pub async fn begin(&self, attributes: Value, cap: Option<i32>) -> Attempt {
        let browser = Secret::generate().unwrap();
        let code = Secret::generate().unwrap();
        let mut start = self
            .service
            .begin(&OAuthIntent {
                browser: &browser,
                source: REQUEST_SOURCE,
                purpose: OAuthPurpose::SignIn,
            })
            .await
            .unwrap();
        if let Some(cap) = cap {
            assert!((1..=PENDING_WINDOW_SECONDS).contains(&cap));
            let rows = sqlx::query("UPDATE auth_oauth_transactions SET created_at=statement_timestamp()-($4::int-$3::int)*interval '1 second',expires_at=statement_timestamp()+$3::int*interval '1 second' WHERE realm_id=$1 AND state_hash=$2")
                .bind(self.realm()).bind(start.transaction.state.verifier().as_slice()).bind(cap).bind(PENDING_WINDOW_SECONDS).execute(&self.pool).await.unwrap().rows_affected();
            assert_eq!(rows, 1, "one owned native pending deadline arranged");
        }
        let (cap, original_window):(i64,bool)=sqlx::query_as("SELECT (extract(epoch FROM expires_at)*1000000)::bigint,expires_at-created_at=$3::int*interval '1 second' FROM auth_oauth_transactions WHERE realm_id=$1 AND state_hash=$2")
            .bind(self.realm()).bind(start.transaction.state.verifier().as_slice()).bind(PENDING_WINDOW_SECONDS).fetch_one(&self.pool).await.unwrap();
        assert!(
            original_window,
            "test infrastructure: original five-minute native window retained"
        );
        start.transaction.expires_us = cap;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&self.pool)
                .await
                .unwrap();
        let mut claims = json!({"iss":ISSUER,"sub":"owned-desktop-subject","aud":CLIENT,"iat":now,"exp":now+TOKEN_LIFETIME_SECONDS,"nonce":start.transaction.proof.nonce().expose()});
        for (name, value) in attributes.as_object().unwrap() {
            claims[name] = value.clone();
        }
        self.provider.issue(
            &code,
            &start.transaction,
            self.policy.configuration(),
            claims,
        );
        Attempt {
            start,
            browser,
            code,
            cap,
        }
    }
    pub async fn rebind(&mut self) {
        assert!(
            self.listener.is_none(),
            "old native receive must have relinquished socket first"
        );
        let c = self.policy.configuration();
        let path = url::Url::parse(c.redirect()).unwrap().path().to_owned();
        let listener = GoogleDesktopListener::bind(self.ip, &path).await.unwrap();
        let connection = OAuthConnection::with_redirect(
            c.realm(),
            c.connection(),
            c.client(),
            ISSUER,
            CLIENT,
            listener.redirect().clone(),
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        self.policy = self
            .store
            .configure_oidc_identity_policy(&policy(connection))
            .await
            .unwrap();
        self.service = service(&self.policy, &self.store, &self.provider);
        self.listener = Some(listener);
    }
    pub fn mapped(&self, completion: GoogleAuthorizationCompletion) -> OidcMappedIdentity {
        let GoogleAuthorizationCompletion::Verified(identity) = completion else {
            panic!("owned signed native positive control must verify");
        };
        self.policy.map(*identity).unwrap()
    }
    pub async fn commit(&self, completion: GoogleAuthorizationCompletion) -> (User, Secret) {
        OidcSignIn::new(self.store.clone())
            .finish(self.mapped(completion))
            .await
            .unwrap()
    }
    pub async fn facts(&self) -> (i64, i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1),(SELECT count(*) FROM auth_oauth_transactions WHERE realm_id=$1)")
            .bind(self.realm()).fetch_one(&self.pool).await.expect("test infrastructure: native scoped authority/pending observation")
    }
    pub async fn mailbox(&self) -> (User, Secret, String) {
        let email = format!("baseline-{}@example.test", Uuid::new_v4());
        let code = Secret::generate().unwrap();
        let browser = Secret::generate().unwrap();
        let session = Secret::generate().unwrap();
        self.store
            .begin_email(
                self.realm(),
                &email,
                code.verifier(),
                browser.verifier(),
                [1; 32],
            )
            .await
            .unwrap();
        let user = self
            .store
            .finish_email(
                self.realm(),
                code.verifier(),
                browser.verifier(),
                session.verifier(),
            )
            .await
            .unwrap();
        (user, session, email)
    }
}
fn policy(connection: OAuthConnection) -> OidcIdentityPolicy {
    OidcIdentityPolicy::new(connection, &[ISSUER], OidcDisplayNameClaim::Subject)
        .unwrap()
        .with_jit(OidcJitPolicy::Allow)
}
fn service(
    policy: &OidcIdentityPolicy,
    store: &Arc<Postgres>,
    provider: &Arc<Provider>,
) -> Arc<GoogleAuthorization> {
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
    Arc::new(
        GoogleAuthorization::new(
            Arc::new(OAuthTransactions::new(
                policy.configuration().clone(),
                store.clone(),
            )),
            exchange,
        )
        .unwrap(),
    )
}
