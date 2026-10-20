use crate::support::oidc_provider::Provider;
use crate::support::{Mail, post};
use auth_core::*;
use auth_postgres::Postgres;
use axum::{
    Router,
    body::Body,
    http::{Request, header},
    response::Response,
};
use easy_auth_axum::{BrowserConfig, OidcWebServices, oidc_web_router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{collections::HashMap, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;

pub(super) const ROOT: &str = "/v1/oidc/sign-in";
pub(super) const ORIGIN: &str = "https://app.example";
pub(super) const CALLBACK: &str = "https://app.example/oidc/callback";
pub(super) struct Fixture {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub provider: Arc<Provider>,
    pub policy: OidcIdentityPolicy,
    pub auth: Auth,
    pub app: Router,
    pub services: OidcWebServices,
}
pub(super) struct Attempt {
    pub cookie: String,
    pub callback: Value,
    pub params: HashMap<String, String>,
}
impl Fixture {
    pub async fn new(pool: PgPool) -> Self {
        Self::with_jit(pool, OidcJitPolicy::Allow).await
    }
    pub async fn with_jit(pool: PgPool, jit: OidcJitPolicy) -> Self {
        Self::with_mapping(pool, jit, OidcDisplayNameClaim::Subject).await
    }
    pub async fn with_mapping(
        pool: PgPool,
        jit: OidcJitPolicy,
        display: OidcDisplayNameClaim,
    ) -> Self {
        let store = Arc::new(Postgres::new(pool.clone()));
        store.migrate().await.expect("test infrastructure: schema");
        let realm = Uuid::new_v4();
        store
            .ensure_realm(realm)
            .await
            .expect("test infrastructure: realm");
        let connection = OAuthConnection::new(
            realm,
            Uuid::new_v4(),
            Uuid::new_v4(),
            "https://issuer.example",
            "client",
            CALLBACK,
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        let definition = OidcIdentityPolicy::new(connection, &["https://issuer.example"], display)
            .unwrap()
            .with_jit(jit);
        let policy = store
            .load_or_initialize_oidc_identity_policy(&definition)
            .await
            .expect("test infrastructure: initial policy");
        let provider = Arc::new(Provider::new(CALLBACK));
        let documents = Arc::new(
            OidcDocuments::new(
                policy.configuration().clone(),
                &["https://issuer.example"],
                store.clone(),
                provider.clone(),
            )
            .unwrap(),
        );
        let transactions = Arc::new(OAuthTransactions::new(
            policy.configuration().clone(),
            store.clone(),
        ));
        let exchange = Arc::new(OidcCodeExchange::new(
            documents,
            store.clone(),
            OidcVerificationPolicy::new(&[OidcSigningAlgorithm::ES256], &[]).unwrap(),
            OidcClientAuthentication::Public,
            provider.clone(),
        ));
        let services = OidcWebServices::new(
            policy.clone(),
            transactions,
            exchange,
            Arc::new(OidcSignIn::new(store.clone())),
            Arc::new(OidcAccountDeletion::new(store.clone())),
        )
        .unwrap();
        let auth = Auth::new(realm, store.clone(), Arc::new(Mail::default()));
        let app = oidc_web_router(
            auth.clone(),
            BrowserConfig::new(ORIGIN, false).unwrap(),
            services.clone(),
        )
        .unwrap();
        Self {
            pool,
            store,
            provider,
            policy,
            auth,
            app,
            services,
        }
    }
    pub async fn post(&self, action: &str, body: Value, cookie: &str) -> Response {
        self.send(post(
            &format!("{ROOT}/{action}"),
            &body.to_string(),
            Some(cookie),
            Some(ORIGIN),
        ))
        .await
    }
    pub async fn send(&self, request: Request<Body>) -> Response {
        self.app.clone().oneshot(request).await.unwrap()
    }
    pub async fn start(&self) -> Attempt {
        let response = self.post("start", json!({}), "").await;
        assert_eq!(
            response.status(),
            200,
            "test infrastructure: valid start control"
        );
        let cookie = cookies(&response);
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            4
        );
        for value in response.headers().get_all(header::SET_COOKIE) {
            let value = value.to_str().unwrap();
            assert!(value.contains("; Path=/; HttpOnly; SameSite=Lax; Max-Age=300; Secure"));
            assert!(!value.contains("Domain="));
        }
        let data = body(response).await;
        assert_eq!(data.as_object().unwrap().len(), 1);
        let url = url::Url::parse(data["authorization_url"].as_str().unwrap()).unwrap();
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(params["redirect_uri"], CALLBACK);
        assert_eq!(
            params["scope"],
            if self.policy.display_name_claim() == OidcDisplayNameClaim::Subject {
                "openid"
            } else {
                "openid profile"
            }
        );
        assert!(!params.contains_key("code_verifier"));
        assert!(!params.contains_key("prompt"));
        assert!(!params.contains_key("max_age"));
        let callback =
            json!({"state":params["state"],"code":"owned-code","issuer":"https://issuer.example"});
        let attempt = Attempt {
            cookie,
            callback,
            params,
        };
        self.prepare(&attempt, "owned", None).await;
        attempt
    }
    pub async fn prepare(&self, attempt: &Attempt, subject: &str, extra: Option<(&str, Value)>) {
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&self.pool)
                .await
                .expect("test infrastructure: database clock");
        let mut claims = json!({"iss":"https://issuer.example","sub":subject,"aud":"client","iat":now,"exp":now+120,"nonce":attempt.params["nonce"],"auth_time":now});
        if let Some((key, value)) = extra {
            claims[key] = value;
        }
        self.provider
            .prepare(claims, attempt.params["code_challenge"].clone());
    }
    pub async fn facts(&self) -> (i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_oidc_identities),(SELECT count(*) FROM auth_oauth_transactions)")
            .fetch_one(&self.pool).await.expect("test infrastructure: observe committed facts")
    }
}
pub(super) async fn body(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
pub(super) async fn text(response: Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}
pub(super) fn cookies(response: &Response) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}
pub(super) fn session(response: &Response) -> String {
    crate::support::cookie(response, "__Host-auth-session=")
}
pub(super) fn no_session(response: &Response) {
    assert!(
        !response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("__Host-auth-session="))
    );
}
pub(super) fn cleared(response: &Response) {
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter(|v| v.to_str().unwrap().contains("Max-Age=0"))
            .count(),
        4
    );
}
