use super::{FixtureResult, mail::DisabledMail, provider, send};
use auth_core::{Auth, SamlIdentityPolicy, SamlJitPolicy, SamlRegistration};
use auth_postgres::Postgres;
use axum::{
    Router,
    extract::{RawQuery, State},
    http::StatusCode,
    response::Html,
    routing::get,
};
use easy_auth_axum::{BrowserConfig, SamlWebServices, experimental_saml_web_router};
use saml_rs::{NameId, NameIdFormat};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub(super) async fn run(pool: &PgPool, origin: String) -> FixtureResult<()> {
    let store = Arc::new(Postgres::new(pool.clone()));
    store.migrate().await?;
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await?;
    let registration = SamlRegistration::unsigned_redirect(
        realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "urn:example:sp",
        "urn:example:idp",
        "https://idp.example/sso",
        &format!("{origin}/saml/acs"),
    )?;
    let policy = store
        .configure_saml_identity_policy(
            &SamlIdentityPolicy::new(registration).with_jit(SamlJitPolicy::Allow),
            &provider::trust(),
        )
        .await?;
    let services =
        SamlWebServices::new(policy.clone(), store.clone(), store.clone(), store.clone())?;
    let app = experimental_saml_web_router(
        Auth::new(realm, store, Arc::new(DisabledMail)),
        BrowserConfig::new(&origin, false)?,
        services,
    )?;
    // This fixture endpoint creates only ordinary IdP protocol messages through
    // the shared library producer. It never seeds a local user/session/proof.
    let idp = Router::new()
        .route("/fixture/saml/authorize", get(authorize))
        .with_state(policy.registration().clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    send(serde_json::json!({"address":listener.local_addr()?.to_string()}))?;
    axum::serve(listener, app.merge(idp))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    let facts: (i64,i64,i64,i64,i64,i64)=tokio::time::timeout(Duration::from_secs(5),sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_saml_identities),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit),(SELECT count(*) FROM auth_saml_requests),(SELECT count(*) FROM auth_saml_replays)").fetch_one(pool)).await??;
    send(
        serde_json::json!({"facts":{"users":facts.0,"identities":facts.1,"sessions":facts.2,"audit":facts.3,"pending":facts.4,"replays":facts.5}}),
    )?;
    Ok(())
}
async fn authorize(
    State(reg): State<SamlRegistration>,
    RawQuery(query): RawQuery,
) -> Result<Html<String>, StatusCode> {
    let query = query.ok_or(StatusCode::BAD_REQUEST)?;
    let url =
        url::Url::parse(&format!("{}?{query}", reg.sso())).map_err(|_| StatusCode::BAD_REQUEST)?;
    let relay = url
        .query_pairs()
        .find(|(name, _)| name == "RelayState")
        .ok_or(StatusCode::BAD_REQUEST)?
        .1
        .into_owned();
    auth_core::Secret::parse(relay.clone()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let response = provider::response_field_from(
        &reg,
        url.as_str(),
        NameId::new("ordinary-subject", Some(NameIdFormat::Persistent)),
        reg.idp_entity(),
        Duration::from_secs(180),
    );
    // The producer's base64 and canonical RelayState contain no HTML delimiters;
    // the ACS is trusted registration, encoded for an attribute context.
    let action = reg
        .acs()
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;");
    Ok(Html(format!(
        "<!doctype html><html><meta charset=\"utf-8\"><body><form method=\"post\" action=\"{action}\"><input type=\"hidden\" name=\"SAMLResponse\" value=\"{response}\"><input type=\"hidden\" name=\"RelayState\" value=\"{relay}\"><button type=\"submit\">Continue</button></form></body></html>"
    )))
}
