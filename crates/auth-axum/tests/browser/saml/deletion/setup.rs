use super::super::setup::{Attempt, Fixture as Base, ORIGIN, provider};
use crate::support::{Mail, cookie, post};
use auth_core::Auth;
use axum::{
    body::Body,
    http::{Request, header},
    response::Response,
};
use easy_auth_axum::{
    BrowserConfig, SamlAccountDeletionWebServices, SamlWebServices, experimental_saml_web_router,
};
use http_body_util::BodyExt;
use saml_rs::{NameId, NameIdFormat};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

pub(super) struct Fixture {
    pub base: Base,
    pub current: String,
}
impl Fixture {
    pub async fn new(pool: PgPool) -> Self {
        let mut base = Base::new(pool).await;
        let services = SamlWebServices::new(
            base.policy.clone(),
            base.store.clone(),
            base.store.clone(),
            base.store.clone(),
        )
        .unwrap()
        .with_account_deletion(
            SamlAccountDeletionWebServices::new(
                base.policy.clone(),
                base.store.clone(),
                base.store.clone(),
                base.store.clone(),
            )
            .unwrap(),
        )
        .unwrap();
        base.app = experimental_saml_web_router(
            Auth::new(
                base.policy.registration().realm(),
                base.store.clone(),
                Arc::new(Mail::default()),
            ),
            BrowserConfig::new(ORIGIN, false).unwrap(),
            services,
        )
        .unwrap();
        let signin = base.start().await;
        let response = base
            .deliver(
                "/v1/saml/sign-in/finish",
                &signin,
                Some(&signin.cookie),
                Some(ORIGIN),
            )
            .await;
        assert_eq!(response.status(), 204);
        let current = cookie(&response, "__Host-auth-session=");
        Self { base, current }
    }
    pub async fn start(&self, subject: &str) -> Attempt {
        let response = self
            .base
            .app
            .clone()
            .oneshot(post(
                "/v1/saml/account-delete/start",
                "{\"confirmation\":\"delete my account\"}",
                Some(&self.current),
                Some(ORIGIN),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let pending = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        for value in response.headers().get_all(header::SET_COOKIE) {
            let value = value.to_str().unwrap();
            assert!(value.starts_with("__Host-auth-saml-delete-"));
            assert!(
                value.contains("Secure")
                    && value.contains("HttpOnly")
                    && value.contains("SameSite=Lax")
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
            .find(|(name, _)| name == "RelayState")
            .unwrap()
            .1
            .into_owned();
        let response = provider::response_field_from(
            self.base.policy.registration(),
            &url,
            NameId::new(subject, Some(NameIdFormat::Persistent)),
            self.base.policy.registration().idp_entity(),
            Duration::from_secs(180),
        );
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("SAMLResponse", &response)
            .append_pair("RelayState", &relay)
            .finish();
        Attempt {
            cookie: format!("{}; {pending}", self.current),
            form,
        }
    }
    pub async fn finish(
        &self,
        attempt: &Attempt,
        confirmation: &str,
        cookie: Option<&str>,
    ) -> Response {
        let phrase = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("confirmation", confirmation)
            .finish();
        self.base
            .deliver(
                "/v1/saml/account-delete/finish",
                &Attempt {
                    cookie: String::new(),
                    form: format!("{}&{phrase}", attempt.form),
                },
                cookie,
                Some(ORIGIN),
            )
            .await
    }
    pub async fn select(&self, attempt: &Attempt, cookie: Option<&str>) -> Response {
        let relay = url::form_urlencoded::parse(attempt.form.as_bytes())
            .find(|(name, _)| name == "RelayState")
            .unwrap()
            .1
            .into_owned();
        self.base
            .app
            .clone()
            .oneshot(post(
                "/v1/saml/operation",
                &serde_json::json!({"RelayState":relay}).to_string(),
                cookie,
                Some(ORIGIN),
            ))
            .await
            .unwrap()
    }
    pub async fn session(&self) -> Response {
        self.base
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/session")
                    .header(header::COOKIE, &self.current)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }
}
