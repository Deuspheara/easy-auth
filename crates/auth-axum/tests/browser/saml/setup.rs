pub(super) use crate::support::saml_provider as provider;

use crate::support::{Mail, post};
use auth_core::{Auth, SamlIdentityPolicy, SamlJitPolicy, SamlRegistration};
use auth_postgres::Postgres;
use axum::{
    Router,
    body::Body,
    http::{Request, header},
    response::Response,
};
use easy_auth_axum::{BrowserConfig, SamlWebServices, experimental_saml_web_router};
use http_body_util::BodyExt;
use saml_rs::{NameId, NameIdFormat};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;

pub(super) const ORIGIN: &str = "https://app.example";
pub(super) struct Fixture {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub policy: SamlIdentityPolicy,
    pub app: Router,
}
pub(super) struct Attempt {
    pub cookie: String,
    pub form: String,
}
impl Fixture {
    pub async fn new(pool: PgPool) -> Self {
        let store = Arc::new(Postgres::new(pool.clone()));
        let realm = Uuid::new_v4();
        store.ensure_realm(realm).await.unwrap();
        let reg = SamlRegistration::unsigned_redirect(
            realm,
            Uuid::new_v4(),
            Uuid::new_v4(),
            "urn:example:sp",
            "urn:example:idp",
            "https://idp.example/sso",
            "https://app.example/saml/acs",
        )
        .unwrap();
        let policy = store
            .configure_saml_identity_policy(
                &SamlIdentityPolicy::new(reg).with_jit(SamlJitPolicy::Allow),
                &provider::trust(),
            )
            .await
            .unwrap();
        let services =
            SamlWebServices::new(policy.clone(), store.clone(), store.clone(), store.clone())
                .unwrap();
        let app = experimental_saml_web_router(
            Auth::new(realm, store.clone(), Arc::new(Mail::default())),
            BrowserConfig::new(ORIGIN, false).unwrap(),
            services,
        )
        .unwrap();
        Self {
            pool,
            store,
            policy,
            app,
        }
    }
    pub async fn start(&self) -> Attempt {
        let response = self
            .app
            .clone()
            .oneshot(post("/v1/saml/sign-in/start", "{}", None, Some(ORIGIN)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        for value in response.headers().get_all(header::SET_COOKIE) {
            let value = value.to_str().unwrap();
            assert!(value.starts_with("__Host-auth-saml-"));
            assert!(
                value.contains("HttpOnly")
                    && value.contains("SameSite=Lax")
                    && value.contains("Secure")
                    && !value.contains("Domain=")
            );
        }
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let url = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["authorization_url"]
            .as_str()
            .unwrap()
            .to_owned();
        let relay = url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "RelayState")
            .unwrap()
            .1
            .into_owned();
        assert!(
            !url.contains(
                cookie
                    .split("__Host-auth-saml-browser=")
                    .nth(1)
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
            )
        );
        let response = provider::response_field_from(
            self.policy.registration(),
            &url,
            NameId::new("ordinary-subject", Some(NameIdFormat::Persistent)),
            self.policy.registration().idp_entity(),
            Duration::from_secs(180),
        );
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("SAMLResponse", &response)
            .append_pair("RelayState", &relay)
            .finish();
        Attempt { cookie, form }
    }
    pub async fn deliver(
        &self,
        path: &str,
        attempt: &Attempt,
        cookie: Option<&str>,
        origin: Option<&str>,
    ) -> Response {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        self.app
            .clone()
            .oneshot(request.body(Body::from(attempt.form.clone())).unwrap())
            .await
            .unwrap()
    }
    pub async fn facts(&self) -> (i64, i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_saml_identities),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_saml_replays),(SELECT count(*) FROM auth_saml_requests)").fetch_one(&self.pool).await.unwrap()
    }
}
