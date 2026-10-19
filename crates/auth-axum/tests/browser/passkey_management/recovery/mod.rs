mod binding;
mod boundary;
mod cancellation;
mod contract;
mod lifecycle;
mod pages;
mod rollback;

use super::*;
use auth_core::{
    PasskeyAuthenticationResponse, PasskeyRecoveryClaims, PasskeyRecoveryReplacement,
    PasskeyRecoverySetup, PasskeyRegistrationResponse,
};
use easy_auth_axum::{PasskeyRecoveryServices, experimental_passkey_recovery_router};
use serde_json::json;

const BIND: &str = "/v1/passkeys/recovery/browser";
const START: &str = "/v1/passkeys/recovery/claims/start";
const RESUME: &str = "/v1/passkeys/recovery/claims/resume";
const STATUS: &str = "/v1/passkeys/recovery/claims/status";
const CANCEL: &str = "/v1/passkeys/recovery/claims/cancel";
const CANCEL_CODE: &str = "/v1/passkeys/recovery/claims/cancel-with-code";
const CANCEL_KEY: &str = "/v1/passkeys/recovery/claims/cancel-with-key";
const REPLACE: &str = "/v1/passkeys/recovery/replacement/start";
const REGISTER: &str = "/v1/passkeys/recovery/replacement/registration";
const FINISH: &str = "/v1/passkeys/recovery/replacement/finish";
const RECOVERY_COOKIE: &str = "__Host-auth-passkey-recovery";

struct Recovery {
    f: Fixture,
    app: Router,
    code: Secret,
    cookie: String,
}
impl Recovery {
    async fn new(pool: PgPool, email_free: bool) -> Self {
        let f = Fixture::new(pool, email_free).await;
        let setup = PasskeyRecoverySetup::new(f.auth.realm(), f.service.clone(), f.store.clone());
        let pending = setup.prepare(&f.session, SOURCE).await.unwrap();
        setup
            .confirm(&f.session, SOURCE, pending.id, &pending.code)
            .await
            .unwrap();
        if !email_free {
            assert!(f.auth.deliver_security_notice().await.unwrap());
        }
        let app = experimental_passkey_recovery_router(
            f.auth.clone(),
            BrowserConfig::new(ORIGIN, false).unwrap(),
            services(&f),
        )
        .unwrap();
        let response = send(&app, BIND, json!({}), None).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        Self {
            f,
            app,
            code: pending.code,
            cookie,
        }
    }
    async fn start(&self) -> serde_json::Value {
        let response = send(
            &self.app,
            START,
            json!({"account_id":self.f.owner,"code":self.code.expose()}),
            Some(&self.cookie),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        json(response).await
    }
    fn target(&self, claim: &serde_json::Value) -> serde_json::Value {
        json!({"account_id":self.f.owner,"claim_id":claim["claim_id"]})
    }
    async fn mature(&self, claim: &serde_json::Value) {
        let required:bool=sqlx::query_scalar("SELECT notification_required FROM auth_passkey_recovery_claims WHERE realm_id=$1 AND id=$2")
            .bind(self.f.auth.realm()).bind(claim["claim_id"].as_str().unwrap().parse::<Uuid>().unwrap()).fetch_one(&self.f.pool).await.unwrap();
        if required {
            assert!(self.f.auth.deliver_security_notice().await.unwrap());
        }
        // Clock fixture only, after actual worker acknowledgement when required.
        sqlx::query("WITH instant AS (SELECT clock_timestamp()-interval '2 days' AS started) UPDATE auth_passkey_recovery_claims SET created_at=started,notified_at=CASE WHEN notification_required THEN started ELSE NULL END,not_before=started+interval '1 day' FROM instant WHERE realm_id=$1 AND id=$2")
            .bind(self.f.auth.realm()).bind(claim["claim_id"].as_str().unwrap().parse::<Uuid>().unwrap()).execute(&self.f.pool).await.unwrap();
    }
    async fn assertion(
        &self,
        claim: &serde_json::Value,
    ) -> (Uuid, PasskeyAuthenticationResponse, SoftToken) {
        let response = send(&self.app, REPLACE, self.target(claim), Some(&self.cookie)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let body = json(response).await;
        let id: Uuid = body["transaction_id"].as_str().unwrap().parse().unwrap();
        let mut options: auth_core::PasskeyCreationOptions =
            serde_json::from_value(body["options"].clone()).unwrap();
        let selection = options.public_key.authenticator_selection.as_mut().unwrap();
        assert!(selection.require_resident_key);
        // Pinned SoftToken rejects residence; adjust the test client hint only.
        // Production options and private state retain all protocol requirements.
        selection.require_resident_key = false;
        selection.resident_key = None;
        let (mut token, _) = SoftToken::new(true).unwrap();
        let registration: PasskeyRegistrationResponse = token
            .perform_register(ORIGIN.parse().unwrap(), options.public_key, 120_000)
            .unwrap();
        let response=send(&self.app,REGISTER,json!({"account_id":self.f.owner,"claim_id":claim["claim_id"],"transaction_id":id,"credential":registration}),Some(&self.cookie)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let options: auth_core::PasskeyAuthenticationOptions =
            serde_json::from_value(json(response).await["options"].clone()).unwrap();
        let signed = token
            .perform_auth(ORIGIN.parse().unwrap(), options.public_key, 120_000)
            .unwrap();
        (id, signed, token)
    }
    fn finish_body(
        &self,
        claim: &serde_json::Value,
        id: Uuid,
        signed: &PasskeyAuthenticationResponse,
    ) -> serde_json::Value {
        json!({"account_id":self.f.owner,"claim_id":claim["claim_id"],"transaction_id":id,"credential":signed})
    }
    async fn snapshot(&self) -> Vec<String> {
        let mut result = Vec::new();
        for table in [
            "auth_users",
            "auth_sessions",
            "auth_passkeys",
            "auth_passkey_recovery_codes",
            "auth_passkey_recovery_claims",
            "auth_passkey_recovery_replacements",
            "auth_security_notifications",
            "auth_audit",
        ] {
            result.push(sqlx::query_scalar(&format!("SELECT coalesce(string_agg(row_to_json(t)::text,E'\n' ORDER BY row_to_json(t)::text),'') FROM {table} t WHERE realm_id=$1"))
                .bind(self.f.auth.realm()).fetch_one(&self.f.pool).await.unwrap());
        }
        result
    }
}
fn services(f: &Fixture) -> PasskeyRecoveryServices {
    let realm = f.auth.realm();
    PasskeyRecoveryServices {
        enrollment: f.enrollment.clone(),
        sign_in: f.sign_in.clone(),
        signup: Arc::new(PasskeySignup::new(
            realm,
            f.service.clone(),
            f.store.clone(),
        )),
        management: Arc::new(PasskeyManagement::new(
            realm,
            f.service.clone(),
            f.store.clone(),
        )),
        setup: Arc::new(PasskeyRecoverySetup::new(
            realm,
            f.service.clone(),
            f.store.clone(),
        )),
        claims: Arc::new(PasskeyRecoveryClaims::new(
            realm,
            f.service.clone(),
            f.store.clone(),
        )),
        replacement: Arc::new(PasskeyRecoveryReplacement::new(
            realm,
            f.service.clone(),
            f.store.clone(),
        )),
    }
}
async fn send(app: &Router, path: &str, body: serde_json::Value, cookie: Option<&str>) -> Response {
    app.clone()
        .oneshot(post(path, &body.to_string(), cookie, Some(ORIGIN)))
        .await
        .unwrap()
}
async fn rejected(response: Response, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert!(response.headers().get(header::LOCATION).is_none());
    assert!(
        json(response).await == json!({"code":code}),
        "generic failure must not echo proofs or private state"
    );
}
