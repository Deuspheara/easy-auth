mod boundary;
mod contract;
mod lifecycle;
#[cfg(feature = "passkey-recovery")]
mod recovery;
#[cfg(feature = "passkey-recovery-setup")]
mod recovery_setup;

use crate::support::{Mail, post};
use auth_core::{
    Auth, PasskeyEnrollment, PasskeyManagement, PasskeyService, PasskeySignIn, PasskeySignup,
    Repository, Secret,
};
use auth_postgres::Postgres;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use easy_auth_axum::{BrowserConfig, experimental_passkey_management_router};
use http_body_util::BodyExt;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

const ORIGIN: &str = "https://app.example";
const INVENTORY: &str = "/v1/passkeys";
const RENAME: &str = "/v1/passkeys/rename";
const REMOVE: &str = "/v1/passkeys/remove";
const SOURCE: &str = "127.0.0.1";

struct Fixture {
    pool: PgPool,
    app: Router,
    auth: Auth,
    store: Arc<Postgres>,
    service: Arc<PasskeyService>,
    enrollment: Arc<PasskeyEnrollment>,
    sign_in: Arc<PasskeySignIn>,
    session: Secret,
    browser: Secret,
    mailbox_cookie: String,
    owner: Uuid,
}

impl Fixture {
    async fn new(pool: PgPool, email_free: bool) -> Self {
        let store = Arc::new(Postgres::new(pool.clone()));
        let realm = Uuid::new_v4();
        store.ensure_realm(realm).await.unwrap();
        let service = Arc::new(PasskeyService::new(ORIGIN, "Example").unwrap());
        let enrollment = Arc::new(PasskeyEnrollment::new(
            realm,
            service.clone(),
            store.clone(),
        ));
        let sign_in = Arc::new(PasskeySignIn::new(realm, service.clone(), store.clone()));
        let auth = Auth::new(realm, store.clone(), Arc::new(Mail::default()));
        let app = compose(&auth, &store, &service, &enrollment, &sign_in);
        // Repository mailbox fixture; genuine passkey proof is performed below.
        let token = Secret::generate().unwrap();
        let browser = Secret::generate().unwrap();
        store
            .begin_email(
                realm,
                "management@example.test",
                token.verifier(),
                browser.verifier(),
                [1; 32],
            )
            .await
            .unwrap();
        let mailbox = Secret::generate().unwrap();
        let user = store
            .finish_email(
                realm,
                token.verifier(),
                browser.verifier(),
                mailbox.verifier(),
            )
            .await
            .unwrap();
        let mailbox_cookie = format!("__Host-auth-session={}", mailbox.expose());
        let mut f = Self {
            pool,
            app,
            auth,
            store,
            service,
            enrollment,
            sign_in,
            session: mailbox,
            browser,
            mailbox_cookie,
            owner: user.id,
        };
        let (_, mut token) = f.add_key("First key").await;
        f.session = f.login(&mut token).await;
        if email_free {
            // Storage-policy setup only. The live session above came from a real assertion.
            sqlx::query("UPDATE auth_users SET email=NULL,email_verified_at=NULL,display_name='Key owner',authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2")
                .bind(f.auth.realm()).bind(f.owner).execute(&f.pool).await.unwrap();
        }
        f
    }

    fn cookie(&self) -> String {
        format!("__Host-auth-session={}", self.session.expose())
    }

    async fn add_key(&self, label: &str) -> (Uuid, SoftToken) {
        let pending = self
            .enrollment
            .begin(&self.session, &self.browser, SOURCE, label)
            .await
            .unwrap();
        let (mut token, _) = SoftToken::new(true).unwrap();
        let response = token
            .perform_register(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
            .unwrap();
        let id = self
            .enrollment
            .finish(
                &self.session,
                &self.browser,
                SOURCE,
                pending.transaction,
                &response,
            )
            .await
            .unwrap();
        (id, token)
    }

    async fn login(&self, token: &mut SoftToken) -> Secret {
        let pending = self
            .sign_in
            .begin_account(self.owner, &self.browser, SOURCE)
            .await
            .unwrap();
        let response = token
            .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
            .unwrap();
        self.sign_in
            .finish(&self.browser, SOURCE, pending.transaction, &response)
            .await
            .unwrap()
    }

    async fn get(&self, path: &str, cookie: &str) -> Response {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn mutate(&self, path: &str, body: &serde_json::Value) -> Response {
        self.app
            .clone()
            .oneshot(post(
                path,
                &body.to_string(),
                Some(&self.cookie()),
                Some(ORIGIN),
            ))
            .await
            .unwrap()
    }

    async fn keys(&self) -> Vec<serde_json::Value> {
        let response = self.get(INVENTORY, &self.cookie()).await;
        assert_eq!(response.status(), StatusCode::OK);
        json(response).await["passkeys"].as_array().unwrap().clone()
    }
}

fn compose(
    auth: &Auth,
    store: &Arc<Postgres>,
    service: &Arc<PasskeyService>,
    enrollment: &Arc<PasskeyEnrollment>,
    sign_in: &Arc<PasskeySignIn>,
) -> Router {
    experimental_passkey_management_router(
        auth.clone(),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        enrollment.clone(),
        sign_in.clone(),
        Arc::new(PasskeySignup::new(
            auth.realm(),
            service.clone(),
            store.clone(),
        )),
        Arc::new(PasskeyManagement::new(
            auth.realm(),
            service.clone(),
            store.clone(),
        )),
    )
    .unwrap()
}

async fn json(response: Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
