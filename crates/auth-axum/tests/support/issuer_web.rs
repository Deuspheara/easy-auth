use crate::support::{Mail, cookie, post, sign_in};
use auth_core::*;
use auth_postgres::Postgres;
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use easy_auth_axum::{BrowserConfig, IssuerWebServices, experimental_issuer_web_router};
use http_body_util::BodyExt;
use josekit::{jwk::KeyPair, jws::RS256};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;

pub(crate) const ORIGIN: &str = "https://app.example";
pub(crate) enum Profile {
    Public,
    Confidential,
    Native,
}
pub(crate) struct Fixture {
    pub(crate) pool: PgPool,
    pub(crate) store: Arc<Postgres>,
    pub(crate) realm: Uuid,
    pub(crate) app: Router,
    pub(crate) key: Arc<IssuerSigningKey>,
    pub(crate) client: IssuerClientRegistration,
    pub(crate) secret: Option<Secret>,
    pub(crate) current: String,
    pub(crate) pkce: IssuerPkceVerifier,
    pub(crate) verifier: String,
    pub(crate) redirect: String,
}
impl Fixture {
    pub(crate) async fn new(pool: PgPool, profile: Profile) -> Self {
        let store = Arc::new(Postgres::new(pool.clone()));
        let realm = Uuid::new_v4();
        store.ensure_realm(realm).await.unwrap();
        let authority = IssuerAuthority::new(realm, ORIGIN).unwrap();
        let pair = RS256.generate_key_pair(2048).unwrap();
        let key = Arc::new(
            IssuerSigningKey::from_pkcs8_pem(
                Uuid::new_v4(),
                String::from_utf8(pair.to_pem_private_key()).unwrap(),
            )
            .unwrap(),
        );
        let now: i64 =
            sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
                .fetch_one(&pool)
                .await
                .unwrap();
        store
            .publish_issuer_key(
                &IssuerKeyPublication::new(
                    authority.clone(),
                    key.public_key().unwrap(),
                    now - 1_000_000,
                    now + 3_600_000_000,
                    now + 3_900_000_000,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let revision = store
            .activate_issuer_key(&authority, key.id())
            .await
            .unwrap();
        store
            .enable_issuer_signing(&authority, revision)
            .await
            .unwrap();
        let secret = matches!(profile, Profile::Confidential).then(|| Secret::generate().unwrap());
        let redirect = if matches!(profile, Profile::Native) {
            "http://127.0.0.1:49152/callback"
        } else {
            "https://client.example/cb?fixed=%2f"
        }
        .to_owned();
        let client = if let Some(secret) = &secret {
            IssuerClientRegistration::confidential(realm, Uuid::new_v4(), &[&redirect], secret)
        } else if matches!(profile, Profile::Native) {
            IssuerClientRegistration::public_native_loopback(realm, Uuid::new_v4(), &[&redirect])
        } else {
            IssuerClientRegistration::public(realm, Uuid::new_v4(), &[&redirect])
        }
        .unwrap();
        let client = store.configure_issuer_client(&client).await.unwrap();
        let services =
            IssuerWebServices::new(authority, store.clone(), store.clone(), vec![key.clone()])
                .unwrap();
        let mail = Arc::new(Mail::default());
        let app = experimental_issuer_web_router(
            Auth::new(realm, store.clone(), mail.clone()),
            BrowserConfig::new(ORIGIN, false).unwrap(),
            services,
        )
        .unwrap();
        let current = sign_in(&app, &mail, "owner@example.test").await;
        let verifier = Secret::generate().unwrap().expose().to_owned();
        let pkce = IssuerPkceVerifier::parse(verifier.clone()).unwrap();
        Self {
            pool,
            store,
            realm,
            app,
            key,
            client,
            secret,
            current,
            pkce,
            verifier,
            redirect,
        }
    }
    pub(crate) async fn code(&self) -> Secret {
        let input = json!({"client_id":self.client.client(),"response_type":"code","redirect_uri":self.redirect,"scope":"openid","state":"client-state","nonce":"client-nonce","code_challenge":self.pkce.challenge(),"code_challenge_method":"S256"});
        let parsed = self.approve(&input).await;
        Secret::parse(
            parsed
                .query_pairs()
                .find(|(k, _)| k == "code")
                .unwrap()
                .1
                .into_owned(),
        )
        .unwrap()
    }
    pub(crate) async fn approve(&self, input: &Value) -> url::Url {
        let response = self
            .app
            .clone()
            .oneshot(post(
                "/v1/oidc/consent/prepare",
                &input.to_string(),
                Some(&self.current),
                Some(ORIGIN),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let proofs = format!(
            "{}; {}; {}; {}",
            self.current,
            cookie(&response, "__Host-auth-issuer-browser="),
            cookie(&response, "__Host-auth-issuer-handle="),
            cookie(&response, "__Host-auth-issuer-operation=")
        );
        let pending = read(response).await;
        let response = self
            .app
            .clone()
            .oneshot(post(
                "/v1/oidc/consent/approve",
                &json!({"authorization":pending["authorization"]}).to_string(),
                Some(&proofs),
                Some(ORIGIN),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let returned = read(response).await;
        url::Url::parse(returned["redirect_uri"].as_str().unwrap()).unwrap()
    }
    pub(crate) fn body(&self, code: &Secret) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("client_id", &self.client.client().to_string())
            .append_pair("code", code.expose())
            .append_pair("redirect_uri", &self.redirect)
            .append_pair("code_verifier", &self.verifier)
            .finish()
    }
    pub(crate) fn basic(&self) -> Option<String> {
        self.secret.as_ref().map(|secret| {
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", self.client.client(), secret.expose()))
            )
        })
    }
    pub(crate) async fn send(&self, body: String, authentication: Option<&str>) -> Response {
        self.app
            .clone()
            .oneshot(token_request("/oidc/token", body, authentication, true))
            .await
            .unwrap()
    }
    pub(crate) async fn facts(&self) -> (i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_access_tokens WHERE realm_id=$1)")
            .bind(self.realm).fetch_one(&self.pool).await.unwrap()
    }
}
pub(crate) fn token_request(
    path: &str,
    body: String,
    authentication: Option<&str>,
    peer: bool,
) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(value) = authentication {
        request = request.header(header::AUTHORIZATION, value);
    }
    if peer {
        request = request.extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 49100))));
    }
    request.body(Body::from(body)).unwrap()
}
pub(crate) fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}
pub(crate) async fn read(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
