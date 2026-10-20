use super::provider::{CLIENT, ISSUER, Provider};
use auth_core::{MAX_OIDC_DELETION_AUTH_AGE_SECONDS, OAuthConnection, Secret, Verifier};
use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

const MAX_QUERY_BYTES: usize = 16 * 1024;
const TOKEN_LIFETIME_SECONDS: i64 = 120;

#[derive(Clone)]
pub(super) struct Source {
    pub pool: PgPool,
    pub configuration: OAuthConnection,
    pub provider: Arc<Provider>,
}
pub(super) async fn response(State(source): State<Source>, RawQuery(query): RawQuery) -> Response {
    match prepare(&source, query.as_deref()).await {
        Ok(redirect) => Redirect::to(&redirect).into_response(),
        Err(Failure::InvalidRequest) => StatusCode::BAD_REQUEST.into_response(),
        Err(Failure::Unavailable) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
enum Failure {
    InvalidRequest,
    Unavailable,
}

async fn prepare(source: &Source, query: Option<&str>) -> Result<String, Failure> {
    let query = query.ok_or(Failure::InvalidRequest)?;
    if query.len() > MAX_QUERY_BYTES {
        return Err(Failure::InvalidRequest);
    }
    let fields: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
    let field = |name: &str| -> Result<String, Failure> {
        let values: Vec<_> = fields
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.to_string())
            .collect();
        if values.len() != 1 {
            return Err(Failure::InvalidRequest);
        }
        Ok(values[0].clone())
    };
    if field("client_id")? != CLIENT
        || field("redirect_uri")? != source.configuration.redirect()
        || field("code_challenge_method")? != "S256"
        || serde_json::from_str::<serde_json::Value>(&field("claims")?)
            .map_err(|_| Failure::InvalidRequest)?
            != json!({"id_token":{"auth_time":{"essential":true}}})
    {
        return Err(Failure::InvalidRequest);
    }
    let state = Secret::parse(field("state")?).map_err(|_| Failure::InvalidRequest)?;
    let nonce = Secret::parse(field("nonce")?).map_err(|_| Failure::InvalidRequest)?;
    let challenge: Verifier = URL_SAFE_NO_PAD
        .decode(field("code_challenge")?)
        .map_err(|_| Failure::InvalidRequest)?
        .try_into()
        .map_err(|_| Failure::InvalidRequest)?;
    let case = field("fixture_case")?;
    let mut target =
        url::Url::parse(source.configuration.redirect()).map_err(|_| Failure::InvalidRequest)?;
    target
        .query_pairs_mut()
        .append_pair("state", state.expose())
        .append_pair("iss", ISSUER);
    match case.as_str() {
        "denied" | "provider_failure" => {
            target
                .query_pairs_mut()
                .append_pair(
                    "error",
                    if case == "denied" {
                        "access_denied"
                    } else {
                        "server_error"
                    },
                )
                .append_pair("error_description", "private-owned-provider-detail");
        }
        "normal" | "missing_time" | "old_time" | "wrong_nonce" | "bad_query" | "fragment" => {
            let now: i64 =
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(&source.pool)
                    .await
                    .map_err(|_| Failure::Unavailable)?;
            let mut claims = json!({"iss":ISSUER,"aud":CLIENT,"sub":"owned-google-browser","iat":now,"exp":now+TOKEN_LIFETIME_SECONDS,"nonce":nonce.expose()});
            if case != "missing_time" {
                claims["auth_time"] = json!(if case == "old_time" {
                    now - i64::try_from(MAX_OIDC_DELETION_AUTH_AGE_SECONDS)
                        .map_err(|_| Failure::InvalidRequest)?
                        - 1
                } else {
                    now
                });
            }
            if case == "wrong_nonce" {
                claims["nonce"] = json!(
                    Secret::generate()
                        .map_err(|_| Failure::Unavailable)?
                        .expose()
                );
            }
            let code = Secret::generate().map_err(|_| Failure::Unavailable)?;
            source
                .provider
                .issue(&code, challenge, &source.configuration, claims);
            target
                .query_pairs_mut()
                .append_pair("code", code.expose())
                .append_pair("scope", "openid email profile")
                .append_pair("authuser", "0")
                .append_pair("hd", "unused.example")
                .append_pair("prompt", "consent");
            if case == "bad_query" {
                target
                    .query_pairs_mut()
                    .append_pair("state", state.expose());
            }
            if case == "fragment" {
                target.set_fragment(Some("owned-fragment"));
            }
        }
        _ => return Err(Failure::InvalidRequest),
    }
    Ok(target.to_string())
}
