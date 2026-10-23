mod boundary;
mod contract;
mod isolation;
mod lifecycle;
mod rollback;

use crate::support::issuer_web::{Fixture as OnlineFixture, ORIGIN, Profile, read};
use crate::support::{Mail, cookie, post};
use auth_core::*;
use axum::{http::header, response::Response};
use easy_auth_axum::{BrowserConfig, experimental_issuer_native_consent_router};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

struct Fixture {
    base: OnlineFixture,
    policy: IssuerNativeRefreshPolicy,
    mail: Arc<Mail>,
}
impl Fixture {
    async fn new(pool: PgPool) -> Self {
        Self::with_client(pool, None).await
    }
    async fn with_client(pool: PgPool, client: Option<uuid::Uuid>) -> Self {
        // Existing unchanged ordinary key/account producer; no new crypto fixture.
        let mut base = OnlineFixture::new(pool, Profile::Native).await;
        let authority = IssuerAuthority::new(base.realm, ORIGIN).unwrap();
        base.client = base
            .store
            .configure_issuer_client(
                &IssuerClientRegistration::public_native_refresh_loopback(
                    base.realm,
                    client.unwrap_or(base.client.client()),
                    &[&base.redirect],
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let policy = base
            .store
            .configure_issuer_native_refresh_policy(
                &IssuerNativeRefreshPolicy::new(authority.clone(), base.client.clone(), 3600, 600)
                    .unwrap(),
            )
            .await
            .unwrap();
        base.store
            .enable_issuer_native_refresh_policy(&policy)
            .await
            .unwrap();
        let mail = Arc::new(Mail::default());
        base.app = experimental_issuer_native_consent_router(
            Auth::new(base.realm, base.store.clone(), mail.clone()),
            BrowserConfig::new(ORIGIN, false).unwrap(),
            Arc::new(IssuerAuthorization::new(
                authority.clone(),
                base.store.clone(),
            )),
            Arc::new(IssuerNativeAuthorization::new(
                authority,
                base.store.clone(),
            )),
        )
        .unwrap();
        Self { base, policy, mail }
    }
    fn input(&self) -> Value {
        json!({"client_id":self.base.client.client(),"response_type":"code",
            "redirect_uri":self.base.redirect,"scope":"openid offline_access",
            "state":"native-http-state","nonce":"native-http-nonce",
            "code_challenge":self.base.pkce.challenge(),"code_challenge_method":"S256",
            "prompt":"consent"})
    }
    async fn send(&self, action: &str, body: &Value, cookies: &str) -> Response {
        self.base
            .app
            .clone()
            .oneshot(post(
                &format!("/v1/oidc/native/consent/{action}"),
                &body.to_string(),
                Some(cookies),
                Some(ORIGIN),
            ))
            .await
            .unwrap()
    }
    async fn prepare(&self) -> (String, Value) {
        let response = self
            .send("prepare", &self.input(), &self.base.current)
            .await;
        assert_eq!(response.status(), 200);
        let proofs = format!(
            "{}; {}; {}; {}",
            self.base.current,
            cookie(&response, "__Host-auth-issuer-browser="),
            cookie(&response, "__Host-auth-issuer-handle="),
            cookie(&response, "__Host-auth-issuer-operation=")
        );
        (proofs, read(response).await)
    }
    async fn facts(&self) -> (i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_issuer_authorizations WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_native_consents WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_native_families WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='issuer_authorized')")
            .bind(self.base.realm).fetch_one(&self.base.pool).await.unwrap()
    }
}
