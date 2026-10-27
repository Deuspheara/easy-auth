use super::provider::{CLIENT, ISSUER, Provider};
use auth_core::{OAuthConnection, Secret};
use axum::{
    Json,
    extract::{RawQuery, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::{Arc, atomic::Ordering};

#[derive(Clone)]
pub(super) struct Source {
    pub pool: PgPool,
    pub configuration: OAuthConnection,
    pub provider: Arc<Provider>,
}
pub(super) async fn response(State(source): State<Source>, RawQuery(query): RawQuery) -> Response {
    match prepare(&source, query.as_deref()).await {
        Ok(html) => Html(html).into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}
async fn prepare(
    source: &Source,
    query: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let query = query.ok_or("missing owned authorization request")?;
    if query.len() > 16384 {
        return Err("oversized owned request".into());
    }
    let fields: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
    let field = |name: &str| -> Result<String, Box<dyn std::error::Error>> {
        let values: Vec<_> = fields
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.to_string())
            .collect();
        if values.len() != 1 {
            return Err("one owned public field required".into());
        }
        Ok(values[0].clone())
    };
    if field("client_id")? != CLIENT
        || field("redirect_uri")? != source.configuration.redirect()
        || field("response_type")? != "code"
        || field("response_mode")? != "form_post"
        || field("scope")? != "email name"
        || fields.len() != 8
    {
        return Err("invalid owned Apple request".into());
    }
    let state = Secret::parse(field("state")?)?;
    let nonce = Secret::parse(field("nonce")?)?;
    let case = field("fixture_case")?;
    let mut returned = vec![("state", state.expose().to_owned())];
    match case.as_str() {
        "denied" => returned.push(("error", "user_cancelled_authorize".to_owned())),
        "provider_failure" => returned.push(("error", "server_error".to_owned())),
        "normal" | "wrong_nonce" | "bad_form" | "profile" | "other_subject" => {
            let now: i64 =
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(&source.pool)
                    .await?;
            let mut claims = json!({"iss":ISSUER,"aud":CLIENT,"sub":"owned-apple-browser","iat":now,"exp":now+120,"nonce":nonce.expose()});
            if case == "other_subject" {
                claims["sub"] = json!("owned-other-apple-browser");
            }
            if case == "wrong_nonce" {
                claims["nonce"] = json!(Secret::generate()?.expose());
            }
            let code = Secret::generate()?;
            source
                .provider
                .issue(&code, claims, Some(source.configuration.redirect()));
            returned.push(("code", code.expose().to_owned()));
            if case == "bad_form" {
                returned.push(("state", state.expose().to_owned()));
            }
            if case == "profile" {
                returned.push(("user",json!({"name":{"firstName":"<script>globalThis.ownedXss=true</script>"},"email":"unsigned@example.com"}).to_string()));
            }
        }
        _ => return Err("unknown owned case".into()),
    }
    let inputs = returned
        .into_iter()
        .map(|(name, value)| {
            format!(
                "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
                attribute(&value)
            )
        })
        .collect::<String>();
    // Served at Apple's origin only inside the intercepted, owned browser context.
    // Actual browser form POST establishes cross-site cookie behavior; it grants no local authority.
    Ok(format!(
        "<!doctype html><html lang=\"en\"><title>Owned Apple producer</title><body><form id=\"return\" method=\"post\" action=\"{}\">{inputs}</form><script>document.getElementById('return').submit()</script></body></html>",
        attribute(source.configuration.redirect())
    ))
}
fn attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) async fn facts(State(source): State<Source>) -> Response {
    match snapshot(&source).await {
        Ok(value) => Json(value).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
pub(super) async fn snapshot(source: &Source) -> Result<Value, sqlx::Error> {
    let facts:(i64,i64,i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1),(SELECT count(*) FROM auth_oauth_transactions WHERE realm_id=$1)").bind(source.configuration.realm()).fetch_one(&source.pool).await?;
    Ok(
        json!({"users":facts.0,"identities":facts.1,"sessions":facts.2,"audit":facts.3,"pending":facts.4,"posts":source.provider.posts.load(Ordering::SeqCst),"signed":source.provider.signed.load(Ordering::SeqCst)}),
    )
}
