use super::provider::{CLIENT, ISSUER, Provider};
use crate::support::{Mail, post};
use auth_core::*;
use auth_postgres::Postgres;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use easy_auth_axum::{BrowserConfig, GoogleWebServices, experimental_google_web_router};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

pub(super) const ORIGIN: &str = "https://app.example";
pub(super) const ROOT: &str = "/v1/google/sign-in";
pub(super) const DELETE: &str = "/v1/account/google-delete";
pub(super) struct Fixture {
    pub app: Router,
    pub store: Arc<Postgres>,
    pub provider: Arc<Provider>,
    pub pool: PgPool,
    pub policy: OidcIdentityPolicy,
    pub auth: Auth,
    pub services: GoogleWebServices,
}
pub(super) struct Attempt {
    pub cookie: String,
    pub url: url::Url,
}
impl Fixture {
    pub async fn new(pool: PgPool) -> Self {
        Self::with_origin(pool, ORIGIN).await
    }
    pub async fn with_origin(pool: PgPool, origin: &str) -> Self {
        let store = Arc::new(Postgres::new(pool.clone()));
        store
            .migrate()
            .await
            .expect("test infrastructure: Google HTTP schema");
        let realm = Uuid::new_v4();
        store.ensure_realm(realm).await.unwrap();
        let config = OAuthConnection::new(
            realm,
            Uuid::new_v4(),
            Uuid::new_v4(),
            ISSUER,
            CLIENT,
            &format!("{origin}/google/callback"),
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        let policy = store
            .configure_oidc_identity_policy(
                &OidcIdentityPolicy::new(config, &[ISSUER], OidcDisplayNameClaim::Subject)
                    .unwrap()
                    .with_jit(OidcJitPolicy::Allow),
            )
            .await
            .unwrap();
        let provider = Provider::new();
        let exchange = Arc::new(
            GoogleCodeExchange::new(
                policy.configuration().clone(),
                store.clone(),
                store.clone(),
                provider.authentication(),
                provider.clone(),
                provider.clone(),
            )
            .unwrap()
            .with_session_age_claims(),
        );
        let services = GoogleWebServices::new(
            policy.clone(),
            Arc::new(OAuthTransactions::new(
                policy.configuration().clone(),
                store.clone(),
            )),
            exchange,
            Arc::new(OidcSignIn::new(store.clone())),
            Arc::new(OidcAccountDeletion::new(store.clone())),
        )
        .unwrap();
        let auth = Auth::new(realm, store.clone(), Arc::new(Mail::default()));
        let app = experimental_google_web_router(
            auth.clone(),
            BrowserConfig::new(origin, false).unwrap(),
            services.clone(),
        )
        .unwrap();
        Self {
            app,
            store,
            provider,
            pool,
            policy,
            auth,
            services,
        }
    }
    pub fn origin(&self) -> String {
        url::Url::parse(self.policy.configuration().redirect())
            .unwrap()
            .origin()
            .ascii_serialization()
    }
    pub fn realm(&self) -> Uuid {
        self.policy.configuration().realm()
    }
    pub async fn send(&self, request: Request<Body>) -> Response {
        self.app.clone().oneshot(request).await.unwrap()
    }
    pub async fn post(&self, root: &str, action: &str, body: Value, cookie: &str) -> Response {
        self.send(post(
            &format!("{root}/{action}"),
            &body.to_string(),
            Some(cookie),
            Some(&self.origin()),
        ))
        .await
    }
    pub async fn start(&self, root: &str, session: &str) -> Attempt {
        let body = if root == DELETE {
            json!({"confirmation":"delete my account"})
        } else {
            json!({})
        };
        let response = self.post(root, "start", body, session).await;
        assert_eq!(
            response.status(),
            200,
            "test infrastructure: valid Google HTTP start"
        );
        assert_eq!(response.headers().get_all("set-cookie").iter().count(), 4);
        let cookie = cookies(&response);
        let url = url::Url::parse(
            body_json(response).await["authorization_url"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(url.origin().ascii_serialization(), ISSUER);
        Attempt { cookie, url }
    }
    pub async fn now(&self) -> i64 {
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&self.pool)
            .await
            .expect("test infrastructure: real Google HTTP clock")
    }
    pub async fn issue(&self, a: &Attempt, attributes: Value) -> String {
        let field = |name: &str| {
            let values: Vec<_> = a
                .url
                .query_pairs()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
                .collect();
            assert_eq!(values.len(), 1, "one public authorization field required");
            values[0].clone()
        };
        assert_eq!(field("client_id"), CLIENT);
        assert!(
            field("redirect_uri") == self.policy.configuration().redirect(),
            "original public redirect required"
        );
        assert_eq!(field("code_challenge_method"), "S256");
        let challenge: Verifier = URL_SAFE_NO_PAD
            .decode(field("code_challenge"))
            .expect("test infrastructure: public S256 encoding")
            .try_into()
            .unwrap();
        let now = self.now().await;
        let mut claims = json!({"iss":ISSUER,"aud":CLIENT,"sub":"owned-google-http","nonce":field("nonce"),"iat":now,"exp":now+120});
        for (key, value) in attributes.as_object().unwrap() {
            claims[key] = value.clone();
        }
        let code = Secret::generate().unwrap();
        self.provider
            .issue(&code, challenge, self.policy.configuration(), claims);
        callback(a, Some(code.expose()), None)
    }
    pub async fn signin(&self) -> String {
        let a = self.start(ROOT, "").await;
        let query = self.fresh(&a).await;
        let response = self
            .post(ROOT, "finish", json!({"query":query}), &a.cookie)
            .await;
        assert_eq!(
            response.status(),
            204,
            "test infrastructure: actual signed Google sign-in control"
        );
        session(&response)
    }
    pub async fn fresh(&self, a: &Attempt) -> String {
        self.issue(a, json!({"auth_time":self.now().await})).await
    }
    pub async fn facts(&self) -> (i64, i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1),(SELECT count(*) FROM auth_oauth_transactions WHERE realm_id=$1)")
            .bind(self.realm()).fetch_one(&self.pool).await.expect("test infrastructure: scoped Google HTTP facts")
    }
}
pub(super) fn callback(a: &Attempt, code: Option<&str>, error: Option<&str>) -> String {
    let state = a
        .url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .into_owned();
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("state", &state).append_pair("iss", ISSUER);
    if let Some(code) = code {
        form.append_pair("code", code)
            .append_pair("scope", "openid email profile")
            .append_pair("authuser", "0")
            .append_pair("hd", "ignored.example")
            .append_pair("prompt", "consent");
    }
    if let Some(error) = error {
        form.append_pair("error", error)
            .append_pair("error_description", "private-provider-detail");
    }
    form.finish()
}
pub(super) async fn body_json(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}
pub(super) async fn text(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
pub(super) fn cookies(response: &Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}
pub(super) fn session(response: &Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap())
        .find(|v| v.starts_with("__Host-auth-session=") && !v.ends_with('='))
        .expect("test infrastructure: actual committed protected session")
        .to_owned()
}
pub(super) fn no_session(response: &Response) {
    assert!(
        !response
            .headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("__Host-auth-session=")),
        "no session authority before commit"
    );
}
