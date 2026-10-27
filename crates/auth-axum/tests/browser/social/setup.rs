use crate::{
    apple_provider, google_provider,
    support::{self, Mail},
};
pub(super) use auth_core::*;
use auth_postgres::Postgres;
pub(super) use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use easy_auth_axum::{AppleWebServices, GoogleWebServices, SocialWebServices};
pub(super) use serde_json::{Value, json};
pub(super) use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
pub(super) use uuid::Uuid;

pub(super) const ORIGIN: &str = "https://app.example";
pub(super) struct Fixture {
    pub app: Router,
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub google: Arc<google_provider::Provider>,
    pub apple: Arc<apple_provider::Provider>,
    pub google_policy: OidcIdentityPolicy,
    pub apple_policy: OidcIdentityPolicy,
    pub mail: Arc<Mail>,
    pub auth: Auth,
    pub google_services: GoogleWebServices,
    pub apple_services: AppleWebServices,
    pub services: SocialWebServices,
    #[cfg(feature = "apple-grants-web")]
    pub apple_signer: Arc<AppleClientSecretSigner>,
}
pub(super) struct Attempt {
    pub cookie: String,
    pub url: url::Url,
}
impl Attempt {
    pub fn field(&self, name: &str) -> String {
        let fields: Vec<_> = self
            .url
            .query_pairs()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
            .collect();
        assert_eq!(fields.len(), 1);
        fields[0].clone()
    }
}
impl Fixture {
    pub async fn new(pool: PgPool) -> Self {
        super::composition::create(pool).await
    }
    pub async fn send(&self, req: Request<Body>) -> Response {
        self.app.clone().oneshot(req).await.unwrap()
    }
    pub async fn post(&self, path: &str, body: Value, cookie: &str) -> Response {
        self.send(support::post(
            path,
            &body.to_string(),
            Some(cookie),
            Some(ORIGIN),
        ))
        .await
    }
    pub async fn get(&self, path: &str, cookie: &str) -> Response {
        self.send(
            Request::builder()
                .uri(path)
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
    pub async fn owner(&self, email: &str) -> (Uuid, String) {
        let cookie = support::sign_in(&self.app, &self.mail, email).await;
        let user = body(self.get("/v1/session", &cookie).await).await;
        (
            Uuid::parse_str(user["id"].as_str().unwrap()).unwrap(),
            cookie,
        )
    }
    pub async fn start(&self, provider: &str, owner: Uuid, session: &str) -> Attempt {
        let r = self
            .post(
                &format!("/v1/account/{provider}-link/start"),
                json!({"expected_owner":owner,"confirmation":"link this account"}),
                session,
            )
            .await;
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers().get_all("set-cookie").iter().count(), 4);
        let cookie = format!("{session}; {}", cookies(&r));
        let url = url::Url::parse(body(r).await["authorization_url"].as_str().unwrap()).unwrap();
        Attempt { cookie, url }
    }
    pub async fn issue(&self, provider: &str, a: &Attempt, subject: &str) -> String {
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&self.pool)
                .await
                .unwrap();
        let policy = if provider == "google" {
            &self.google_policy
        } else {
            &self.apple_policy
        };
        let mut claims = json!({"iss":policy.configuration().issuer(),"aud":a.field("client_id"),"sub":subject,
            "nonce":a.field("nonce"),"iat":now,"exp":now+120});
        let code = Secret::generate().unwrap();
        if provider == "google" {
            assert_eq!(a.field("code_challenge_method"), "S256");
            let challenge = URL_SAFE_NO_PAD
                .decode(a.field("code_challenge"))
                .unwrap()
                .try_into()
                .unwrap();
            claims["auth_time"] = json!(now);
            self.google
                .issue(&code, challenge, policy.configuration(), claims);
        } else {
            self.apple
                .issue(&code, claims, Some(policy.configuration().redirect()));
        }
        let mut response = url::form_urlencoded::Serializer::new(String::new());
        response
            .append_pair("state", &a.field("state"))
            .append_pair("code", code.expose());
        if provider == "google" {
            response.append_pair("iss", google_provider::ISSUER);
        }
        response.finish()
    }
    pub async fn finish(&self, provider: &str, a: &Attempt, raw: &str) -> Response {
        let mut input = json!({"confirmation":"link this account"});
        input[if provider == "google" {
            "query"
        } else {
            "response"
        }] = json!(raw);
        self.post(
            &format!("/v1/account/{provider}-link/finish"),
            input,
            &a.cookie,
        )
        .await
    }
    pub async fn inventory(&self, session: &str) -> Value {
        body(self.get("/v1/account/providers", session).await).await
    }
}
pub(super) fn cookies(r: &Response) -> String {
    r.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}
pub(super) fn no_session(r: &Response) {
    assert!(
        !r.headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("__Host-auth-session="))
    );
}
pub(super) async fn body(r: Response) -> Value {
    serde_json::from_slice(&to_bytes(r.into_body(), usize::MAX).await.unwrap()).unwrap()
}
pub(super) async fn text(r: Response) -> String {
    String::from_utf8(to_bytes(r.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
}
