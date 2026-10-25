pub(super) use super::provider::{CLIENT, ISSUER, Provider};
use crate::support::{Mail, post};
pub(super) use auth_core::*;
use auth_postgres::Postgres;
use axum::Router;
pub(super) use axum::{
    body::{Body, to_bytes},
    http::Request,
    response::Response,
};
use easy_auth_axum::{AppleWebServices, BrowserConfig, experimental_apple_web_router};
pub(super) use serde_json::{Value, json};
use sqlx::PgPool;
pub(super) use std::sync::{Arc, atomic::Ordering};
use tower::ServiceExt;
use uuid::Uuid;

pub(super) const ORIGIN: &str = "https://app.example";
pub(super) const ROOT: &str = "/v1/apple/sign-in";
pub(super) struct Fixture {
    pub app: Router,
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub provider: Arc<Provider>,
    pub policy: OidcIdentityPolicy,
    pub auth: Auth,
    pub services: AppleWebServices,
}
pub(super) struct Attempt {
    pub cookie: String,
    pub url: url::Url,
}
impl Attempt {
    pub fn field(&self, name: &str) -> String {
        let values: Vec<_> = self
            .url
            .query_pairs()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .collect();
        assert_eq!(
            values.len(),
            1,
            "one original public Apple authorization member"
        );
        values[0].clone()
    }
}
impl Fixture {
    pub async fn new(pool: PgPool) -> Self {
        Self::with_origin(pool, ORIGIN).await
    }
    pub async fn with_origin(pool: PgPool, origin: &str) -> Self {
        let store = Arc::new(Postgres::new(pool.clone()));
        store.migrate().await.unwrap();
        let realm = Uuid::new_v4();
        store.ensure_realm(realm).await.unwrap();
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
            &format!("{origin}/apple/callback"),
            OAuthMixupDefense::DedicatedRedirect,
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
        let services = AppleWebServices::new(
            policy.clone(),
            Arc::new(OAuthTransactions::new(
                policy.configuration().clone(),
                store.clone(),
            )),
            exchange,
            Arc::new(OidcSignIn::new(store.clone())),
        )
        .unwrap();
        let auth = Auth::new(realm, store.clone(), Arc::new(Mail::default()));
        let app = experimental_apple_web_router(
            auth.clone(),
            BrowserConfig::new(origin, false).unwrap(),
            services.clone(),
        )
        .unwrap();
        Self {
            app,
            pool,
            store,
            provider,
            policy,
            auth,
            services,
        }
    }
    pub fn realm(&self) -> Uuid {
        self.policy.configuration().realm()
    }
    pub fn origin(&self) -> String {
        url::Url::parse(self.policy.configuration().redirect())
            .unwrap()
            .origin()
            .ascii_serialization()
    }
    pub async fn send(&self, request: Request<Body>) -> Response {
        self.app.clone().oneshot(request).await.unwrap()
    }
    pub async fn post(&self, action: &str, body: Value, cookie: &str) -> Response {
        self.send(post(
            &format!("{ROOT}/{action}"),
            &body.to_string(),
            Some(cookie),
            Some(&self.origin()),
        ))
        .await
    }
    pub async fn start(&self) -> Attempt {
        let response = self.post("start", json!({}), "").await;
        assert_eq!(response.status(), 200, "owned Apple start must succeed");
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
    pub async fn issue(&self, attempt: &Attempt, attributes: Value, user: Option<&str>) -> String {
        assert_eq!(attempt.field("client_id"), CLIENT);
        assert!(attempt.field("redirect_uri") == self.policy.configuration().redirect());
        assert_eq!(attempt.field("response_mode"), "form_post");
        assert_eq!(attempt.field("response_type"), "code");
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&self.pool)
                .await
                .unwrap();
        let mut claims = json!({"iss":ISSUER,"aud":CLIENT,"sub":"owned-apple-web","iat":now,"exp":now+120,"nonce":attempt.field("nonce")});
        for (key, value) in attributes.as_object().unwrap() {
            claims[key] = value.clone();
        }
        let code = Secret::generate().unwrap();
        self.provider
            .issue(&code, claims, Some(self.policy.configuration().redirect()));
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("state", &attempt.field("state"))
            .append_pair("code", code.expose());
        if let Some(user) = user {
            form.append_pair("user", user);
        }
        form.finish()
    }
    pub async fn bridge(&self, body: &str, cookie: &str) -> Response {
        self.send(
            Request::builder()
                .method("POST")
                .uri("/apple/callback")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("origin", ISSUER)
                .header("cookie", cookie)
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
    }
    pub async fn facts(&self) -> (i64, i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1),(SELECT count(*) FROM auth_oauth_transactions WHERE realm_id=$1)")
            .bind(self.realm()).fetch_one(&self.pool).await.unwrap()
    }
    pub async fn signin(&self) -> String {
        let a = self.start().await;
        let raw = self.issue(&a, json!({}), None).await;
        let response = self
            .post("finish", json!({"response":raw}), &a.cookie)
            .await;
        assert_eq!(response.status(), 204);
        session(&response)
    }
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
        .expect("session only after commit")
        .to_owned()
}
pub(super) fn no_session(response: &Response) {
    assert!(
        !response
            .headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("__Host-auth-session="))
    );
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
