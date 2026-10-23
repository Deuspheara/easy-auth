mod boundary;
mod lifecycle;

use super::*;
use easy_auth_axum::experimental_issuer_token_management_web_router;

async fn fixture(pool: PgPool, profile: Profile) -> Fixture {
    let mut f = Fixture::new(pool, profile).await;
    let authority = IssuerAuthority::new(f.realm, ORIGIN).unwrap();
    let services = IssuerWebServices::new(
        authority.clone(),
        f.store.clone(),
        f.store.clone(),
        vec![f.key.clone()],
    )
    .unwrap();
    f.app = experimental_issuer_token_management_web_router(
        Auth::new(f.realm, f.store.clone(), Arc::new(Mail::default())),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        services,
        Arc::new(IssuerTokenManagement::new(authority, f.store.clone())),
    )
    .unwrap();
    f
}
async fn issued(f: &Fixture) -> Secret {
    let response = f.send(f.body(&f.code().await), f.basic().as_deref()).await;
    assert_eq!(response.status(), 200);
    let value = read(response).await;
    Secret::parse(value["access_token"].as_str().unwrap().to_owned()).unwrap()
}
fn body(f: &Fixture, token: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("token", token)
        .append_pair("client_id", &f.client.client().to_string())
        .finish()
}
async fn send(f: &Fixture, path: &str, body: String) -> Response {
    f.app
        .clone()
        .oneshot(token_request(path, body, f.basic().as_deref(), true))
        .await
        .unwrap()
}
