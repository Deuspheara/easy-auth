use crate::support::oidc_provider::Provider;
use crate::support::{Mail, post};
use auth_core::*;
use auth_postgres::Postgres;
use axum::{
    Router,
    http::{StatusCode, header},
    response::Response,
};
use easy_auth_axum::{
    BrowserConfig, OidcAccountDeletionServices, experimental_oidc_account_deletion_router,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{collections::HashMap, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;

pub(super) const ROOT: &str = "/v1/account/provider-delete";
pub(super) struct Fixture {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub provider: Arc<Provider>,
    pub policy: OidcIdentityPolicy,
    pub transactions: Arc<OAuthTransactions>,
    pub exchange: Arc<OidcCodeExchange>,
    pub auth: Auth,
    pub services: OidcAccountDeletionServices,
    pub app: Router,
    pub user: User,
    pub session: Secret,
}
pub(super) struct Attempt {
    pub cookie: String,
    pub callback: Value,
    pub url: String,
}
impl Fixture {
    pub async fn new(pool: PgPool) -> Self {
        let store = Arc::new(Postgres::new(pool.clone()));
        store.migrate().await.expect("test infrastructure: schema");
        let realm = Uuid::new_v4();
        store.ensure_realm(realm).await.unwrap();
        let connection = OAuthConnection::new(
            realm,
            Uuid::new_v4(),
            Uuid::new_v4(),
            "https://issuer.example",
            "client",
            "https://app.example/oidc/account-delete/callback",
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        let policy = OidcIdentityPolicy::new(
            connection,
            &["https://issuer.example"],
            OidcDisplayNameClaim::Subject,
        )
        .unwrap()
        .with_jit(OidcJitPolicy::Allow);
        let policy = store.configure_oidc_identity_policy(&policy).await.unwrap();
        let provider = Arc::new(Provider::new(
            "https://app.example/oidc/account-delete/callback",
        ));
        let documents = Arc::new(
            OidcDocuments::new(
                policy.configuration().clone(),
                &["https://issuer.example"],
                store.clone(),
                provider.clone(),
            )
            .unwrap(),
        );
        let verification =
            OidcVerificationPolicy::new(&[OidcSigningAlgorithm::ES256], &[]).unwrap();
        let transactions = Arc::new(OAuthTransactions::new(
            policy.configuration().clone(),
            store.clone(),
        ));
        let exchange = Arc::new(OidcCodeExchange::new(
            documents.clone(),
            store.clone(),
            verification.clone(),
            OidcClientAuthentication::Public,
            provider.clone(),
        ));
        let (user, session) =
            signed_session(&pool, store.clone(), &policy, provider.clone(), "owned").await;
        let services = OidcAccountDeletionServices::new(
            policy.clone(),
            transactions.clone(),
            exchange.clone(),
            Arc::new(OidcAccountDeletion::new(store.clone())),
        )
        .unwrap();
        let auth = Auth::new(realm, store.clone(), Arc::new(Mail::default()));
        let app = experimental_oidc_account_deletion_router(
            auth.clone(),
            BrowserConfig::new("https://app.example", false).unwrap(),
            services.clone(),
        )
        .unwrap();
        Self {
            pool,
            store,
            provider,
            policy,
            transactions,
            exchange,
            auth,
            services,
            app,
            user,
            session,
        }
    }
    pub async fn another_session(&self, subject: &str) -> (User, Secret) {
        signed_session(
            &self.pool,
            self.store.clone(),
            &self.policy,
            self.provider.clone(),
            subject,
        )
        .await
    }
    pub fn session_cookie(&self) -> String {
        format!("__Host-auth-session={}", self.session.expose())
    }
    pub async fn post(&self, action: &str, body: Value, cookie: &str) -> Response {
        self.app
            .clone()
            .oneshot(post(
                &format!("{ROOT}/{action}"),
                &body.to_string(),
                Some(cookie),
                Some("https://app.example"),
            ))
            .await
            .unwrap()
    }
    pub async fn start(&self) -> Attempt {
        let response = self
            .post(
                "start",
                json!({"confirmation":"delete my account"}),
                &self.session_cookie(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut pairs = vec![self.session_cookie()];
        for value in response.headers().get_all(header::SET_COOKIE) {
            let value = value.to_str().unwrap();
            assert!(value.contains("; HttpOnly; SameSite=Lax; Max-Age=300; Secure"));
            assert!(!value.contains("Domain="));
            pairs.push(value.split(';').next().unwrap().to_owned());
        }
        assert_eq!(pairs.len(), 5);
        let data = body(response).await;
        assert_eq!(data.as_object().unwrap().len(), 1);
        let url = data["authorization_url"].as_str().unwrap().to_owned();
        let parsed = url::Url::parse(&url).unwrap();
        let params: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(params["prompt"], "login");
        assert_eq!(params["max_age"], "0");
        assert!(!params.contains_key("code_verifier"));
        let time = now(&self.pool).await;
        self.provider.prepare(json!({"iss":"https://issuer.example","sub":"owned","aud":"client","iat":time,"exp":time+120,"nonce":params["nonce"],"auth_time":time}), params["code_challenge"].clone());
        Attempt {
            cookie: pairs.join("; "),
            callback: json!({"confirmation":"delete my account","state":params["state"],"code":"owned-code","issuer":"https://issuer.example"}),
            url,
        }
    }
    pub async fn exists(&self) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_users WHERE realm_id=$1 AND id=$2)")
            .bind(self.user.realm_id)
            .bind(self.user.id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    pub async fn pending(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM auth_oauth_transactions")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    pub async fn prepare_claims(&self, attempt: &Attempt, subject: &str, age: Option<i64>) {
        let parsed = url::Url::parse(&attempt.url).unwrap();
        let params: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        let time = now(&self.pool).await;
        let mut claims = json!({"iss":"https://issuer.example","sub":subject,"aud":"client","iat":time,"exp":time+120,"nonce":params["nonce"]});
        if let Some(age) = age {
            claims["auth_time"] = json!(time - age);
        }
        self.provider
            .prepare(claims, params["code_challenge"].clone());
    }
}
// Actual signed bootstrap, including new sessions used to test account switching.
// Neither local session time nor token issuance is promoted to auth_time.
async fn signed_session(
    pool: &PgPool,
    store: Arc<Postgres>,
    policy: &OidcIdentityPolicy,
    provider: Arc<Provider>,
    subject: &str,
) -> (User, Secret) {
    let connection = policy.configuration();
    let documents = Arc::new(
        OidcDocuments::new(
            connection.clone(),
            &["https://issuer.example"],
            store.clone(),
            provider.clone(),
        )
        .unwrap(),
    );
    let transactions = OAuthTransactions::new(connection.clone(), store.clone());
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "embedded",
        purpose: OAuthPurpose::SignIn,
    };
    let start = transactions.begin(&intent).await.unwrap();
    let time = now(pool).await;
    let raw = provider.token(json!({"iss":connection.issuer(),"sub":subject,"aud":connection.provider_client(),"iat":time,"exp":time+120,"nonce":start.proof.nonce().expose()}));
    let context = transactions
        .consume(
            &intent,
            &start.state,
            start.proof,
            OAuthCallback {
                redirect: connection.redirect(),
                issuer: Some(connection.issuer()),
            },
        )
        .await
        .unwrap();
    let verification = OidcVerificationPolicy::new(&[OidcSigningAlgorithm::ES256], &[]).unwrap();
    let verified = OidcTokenVerifier::new(documents, store.clone(), verification)
        .verify(context, OidcIdToken::parse(raw).unwrap())
        .await
        .unwrap();
    OidcSignIn::new(store)
        .finish(policy.map(verified).unwrap())
        .await
        .unwrap()
}
pub(super) async fn now(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(pool)
        .await
        .expect("test infrastructure: database clock")
}
pub(super) async fn body(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
pub(super) fn cleared(response: &Response) -> usize {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter(|value| value.to_str().unwrap().contains("Max-Age=0"))
        .count()
}
