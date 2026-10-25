mod boundary;
mod contract;
mod lifecycle;

use crate::support::{Mail, cookie, post, sign_in};
use auth_core::{
    Auth, IssuerAuthority, IssuerAuthorization, IssuerClientRegistration, IssuerPkceVerifier,
    Secret,
};
use auth_postgres::Postgres;
use axum::{
    Router,
    body::Body,
    http::{Request, header},
    response::Response,
};
use easy_auth_axum::{BrowserConfig, experimental_issuer_consent_router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "https://app.example";
struct Fixture {
    pool: PgPool,
    store: Arc<Postgres>,
    realm: Uuid,
    app: Router,
    service: Arc<IssuerAuthorization>,
    client: IssuerClientRegistration,
    current: String,
    mail: Arc<Mail>,
    pkce: IssuerPkceVerifier,
}
struct Attempt {
    cookies: String,
    authorization: Uuid,
}
impl Fixture {
    async fn new(pool: PgPool) -> Self {
        let store = Arc::new(Postgres::new(pool.clone()));
        let realm = Uuid::new_v4();
        store.ensure_realm(realm).await.unwrap();
        let service = Arc::new(IssuerAuthorization::new(
            IssuerAuthority::new(realm, ORIGIN).unwrap(),
            store.clone(),
        ));
        let mail = Arc::new(Mail::default());
        let app = experimental_issuer_consent_router(
            Auth::new(realm, store.clone(), mail.clone()),
            BrowserConfig::new(ORIGIN, false).unwrap(),
            service.clone(),
        )
        .unwrap();
        let current = sign_in(&app, &mail, "owner@example.test").await;
        let client = store
            .configure_issuer_client(
                &IssuerClientRegistration::public_native_loopback(
                    realm,
                    Uuid::new_v4(),
                    &["http://127.0.0.1:49152/callback"],
                )
                .unwrap(),
            )
            .await
            .unwrap();
        Self {
            pool,
            store,
            realm,
            app,
            service,
            client,
            current,
            mail,
            pkce: IssuerPkceVerifier::parse(Secret::generate().unwrap().expose().to_owned())
                .unwrap(),
        }
    }
    fn input(&self) -> Value {
        json!({"client_id":self.client.client(),"response_type":"code","redirect_uri":"http://127.0.0.1:49152/callback","scope":"openid","state":"original-state","nonce":"original-nonce","code_challenge":self.pkce.challenge(),"code_challenge_method":"S256"})
    }
    async fn send(&self, path: &str, body: Value, cookies: &str) -> Response {
        self.app
            .clone()
            .oneshot(post(path, &body.to_string(), Some(cookies), Some(ORIGIN)))
            .await
            .unwrap()
    }
    async fn prepare(&self) -> Attempt {
        let response = self
            .send("/v1/oidc/consent/prepare", self.input(), &self.current)
            .await;
        assert_eq!(response.status(), 200);
        for value in response.headers().get_all(header::SET_COOKIE) {
            let value = value.to_str().unwrap();
            assert!(
                value.contains("Secure")
                    && value.contains("HttpOnly")
                    && value.contains("SameSite=Lax")
                    && value.contains("Path=/")
                    && !value.contains("Domain=")
            );
        }
        let cookies = format!(
            "{}; {}; {}; {}",
            self.current,
            cookie(&response, "__Host-auth-issuer-browser="),
            cookie(&response, "__Host-auth-issuer-handle="),
            cookie(&response, "__Host-auth-issuer-operation=")
        );
        let body = read(response).await;
        assert_eq!(body["client_id"], self.client.client().to_string());
        assert_eq!(body["redirect_uri"], self.input()["redirect_uri"]);
        assert!(
            body.get("handle").is_none()
                && body.get("browser").is_none()
                && body.get("code").is_none()
        );
        Attempt {
            cookies,
            authorization: Uuid::parse_str(body["authorization"].as_str().unwrap()).unwrap(),
        }
    }
    fn decision(attempt: &Attempt) -> Value {
        json!({"authorization":attempt.authorization})
    }
    async fn count(&self, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE realm_id=$1"))
            .bind(self.realm)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}
async fn read(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

mod resume;
