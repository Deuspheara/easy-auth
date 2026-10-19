mod boundary;
mod contract;
mod lifecycle;

use super::*;
use auth_core::PasskeyRecoverySetup;
use serde_json::json;

const PREPARE: &str = "/v1/passkeys/recovery/code/prepare";
const CONFIRM: &str = "/v1/passkeys/recovery/code/confirm";

fn app(f: &Fixture, auth: Auth) -> Router {
    easy_auth_axum::experimental_passkey_recovery_setup_router(
        auth,
        BrowserConfig::new(ORIGIN, false).unwrap(),
        f.enrollment.clone(),
        f.sign_in.clone(),
        Arc::new(PasskeySignup::new(
            f.auth.realm(),
            f.service.clone(),
            f.store.clone(),
        )),
        Arc::new(PasskeyManagement::new(
            f.auth.realm(),
            f.service.clone(),
            f.store.clone(),
        )),
        Arc::new(PasskeyRecoverySetup::new(
            f.auth.realm(),
            f.service.clone(),
            f.store.clone(),
        )),
    )
    .unwrap()
}

async fn send(app: &Router, f: &Fixture, path: &str, body: &serde_json::Value) -> Response {
    app.clone()
        .oneshot(post(
            path,
            &body.to_string(),
            Some(&f.cookie()),
            Some(ORIGIN),
        ))
        .await
        .unwrap()
}

async fn prepare(app: &Router, f: &Fixture) -> (Uuid, Secret) {
    let response = send(app, f, PREPARE, &json!({})).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert!(response.headers().get(header::LOCATION).is_none());
    let body = super::json(response).await;
    let mut keys = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort();
    assert_eq!(keys, ["code", "id"]);
    let id = body["id"].as_str().unwrap().parse().unwrap();
    let code = Secret::parse(body["code"].as_str().unwrap().to_owned()).unwrap();
    (id, code)
}

async fn rejected(response: Response, expected: StatusCode, code: &str) {
    assert_eq!(response.status(), expected);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert!(
        super::json(response).await == json!({"code":code}),
        "generic errors cannot echo a code or private state"
    );
}
