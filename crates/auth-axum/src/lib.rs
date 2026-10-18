//! Same-origin browser transport, shared by embedding and the standalone service.
use auth_core::{Auth, Error, Password, Secret};
use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{net::SocketAddr, time::Duration};
use url::Url;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

#[derive(Clone)]
pub struct BrowserConfig {
    origin: String,
    secure: bool,
}
impl BrowserConfig {
    pub fn new(public_url: &str, development: bool) -> auth_core::Result<Self> {
        let url = Url::parse(public_url).map_err(|_| Error::InvalidInput)?;
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        let secure = url.scheme() == "https";
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.host_str().is_none()
            || !(secure || development && loopback && url.scheme() == "http")
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            origin: url.origin().ascii_serialization(),
            secure,
        })
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    fn session_name(&self) -> &'static str {
        if self.secure {
            "__Host-auth-session"
        } else {
            "auth-session"
        }
    }
    fn browser_name(&self) -> &'static str {
        if self.secure {
            "__Host-auth-browser"
        } else {
            "auth-browser"
        }
    }
    fn reset_name(&self) -> &'static str {
        if self.secure {
            "__Host-auth-reset"
        } else {
            "auth-reset"
        }
    }
    fn cookie(&self, name: &str, secret: Option<&Secret>, max_age: u32) -> HeaderValue {
        let value = format!(
            "{name}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
            secret.map(Secret::expose).unwrap_or(""),
            if self.secure { "; Secure" } else { "" }
        );
        // Names and canonical base64url secrets are controlled by this module.
        HeaderValue::from_str(&value).expect("controlled cookie is a valid header")
    }
}
/// Verify an application's request cookie using the shared core and configured cookie policy.
/// The caller remains responsible for domain-specific authorization.
pub async fn authenticate(
    auth: &Auth,
    browser: &BrowserConfig,
    headers: &HeaderMap,
) -> auth_core::Result<auth_core::User> {
    let secret = read_cookie(headers, browser.session_name())?;
    auth.authenticate(&secret).await
}

#[derive(Clone)]
struct AppState {
    auth: Auth,
    browser: BrowserConfig,
}

pub fn router(auth: Auth, browser: BrowserConfig) -> Router {
    let state = AppState { auth, browser };
    Router::new()
        .route("/healthz", get(health))
        .route("/openapi.json", get(|| async { Json(openapi()) }))
        .route("/readyz", get(ready))
        .route("/v1/email/start", post(start))
        .route("/v1/email/finish", post(finish))
        .route("/v1/password/enroll", post(enroll_password))
        .route("/v1/password/login", post(password_login))
        .route("/v1/password/reset/start", post(start_password_reset))
        .route("/v1/password/reset/finish", post(finish_password_reset))
        .route("/reset", get(|| async { Html(include_str!("reset.html")) }))
        .route(
            "/reset.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("reset.js"),
                )
            }),
        )
        .route("/v1/session", get(session))
        .route("/v1/logout", post(logout))
        .route("/", get(|| async { Html(include_str!("client.html")) }))
        .route(
            "/client.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("client.js"),
                )
            }),
        )
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(state.clone(), boundary))
        .with_state(state)
}
async fn boundary(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let mut response = if request.method() == Method::POST
        && (request.headers().get_all(header::ORIGIN).iter().count() != 1
            || request
                .headers()
                .get(header::ORIGIN)
                .and_then(|v| v.to_str().ok())
                != Some(state.browser.origin()))
    {
        (
            StatusCode::FORBIDDEN,
            Json(json!({"code":"origin_rejected"})),
        )
            .into_response()
    } else {
        match tokio::time::timeout(Duration::from_secs(15), next.run(request)).await {
            Ok(response) => response,
            Err(_) => (
                StatusCode::GATEWAY_TIMEOUT,
                Json(json!({"code":"temporarily_unavailable"})),
            )
                .into_response(),
        }
    };
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"));
    if state.browser.secure {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(&request_id).expect("UUID is header-safe"),
    );
    tracing::info!(
        request_id,
        status = response.status().as_u16(),
        "http_request_completed"
    );
    response
}
enum ApiError {
    Core(Error),
    Body(StatusCode),
}
impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Body(status) = self {
            return (
                status,
                Json(ErrorResponse {
                    code: "invalid_body",
                }),
            )
                .into_response();
        }
        let Self::Core(error) = self else {
            unreachable!()
        };
        let (status, code) = match error {
            Error::InvalidInput => (StatusCode::BAD_REQUEST, "invalid_input"),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "authentication_required"),
            Error::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Error::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
        };
        (status, Json(json!({"code":code}))).into_response()
    }
}
fn read_cookie(headers: &HeaderMap, name: &str) -> auth_core::Result<Secret> {
    let mut value = None;
    for header in headers.get_all(header::COOKIE) {
        let header = header.to_str().map_err(|_| Error::Unauthorized)?;
        for pair in header.split(';') {
            if let Some((key, val)) = pair.trim().split_once('=')
                && key == name
            {
                if value.is_some() {
                    return Err(Error::Unauthorized);
                }
                value = Some(val.to_owned());
            }
        }
    }
    Secret::parse(value.ok_or(Error::Unauthorized)?)
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct EmailInput {
    email: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct FinishInput {
    token: String,
}
#[utoipa::path(post, path = "/v1/email/start", request_body = EmailInput,
    params(("Origin" = String, Header, description = "Exact configured browser origin")),
    responses((status = 202, body = Accepted, description = "Generic response; sets HttpOnly browser binding"),
    (status = 400, body = ErrorResponse), (status = 403, body = ErrorResponse),
    (status = 413, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 429, body = ErrorResponse), (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
async fn start(
    State(state): State<AppState>,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<EmailInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    // Missing ConnectInfo uses a shared embedded bucket; never trust Forwarded/X-Forwarded-For.
    let source = source
        .map(|Extension(ConnectInfo(addr))| addr.ip().to_string())
        .unwrap_or_else(|| "embedded".to_owned());
    let browser = state.auth.start_email(&input.email, &source).await?;
    let mut response = (StatusCode::ACCEPTED, Json(json!({"status":"accepted"}))).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.browser_name(), Some(&browser), 600),
    );
    Ok(response)
}
#[utoipa::path(post, path = "/v1/email/finish", request_body = FinishInput,
    params(("Origin" = String, Header), ("Cookie" = String, Header, description = "Browser binding cookie from start")),
    responses((status = 204, description = "Sets fresh HttpOnly session; clears binding cookie"), (status = 400, body = ErrorResponse),
    (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 413, body = ErrorResponse),
    (status = 415, body = ErrorResponse), (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
async fn finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    input: Result<Json<FinishInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = read_cookie(&headers, state.browser.browser_name())?;
    let session = state
        .auth
        .finish_email(Secret::parse(input.token)?, browser)
        .await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.session_name(), Some(&session), 604800),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        state.browser.cookie(state.browser.browser_name(), None, 0),
    );
    Ok(response)
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct PasswordEnrollmentInput {
    /// NFC normalized; 15–256 Unicode code points, at most 1024 UTF-8 bytes.
    password: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct PasswordLoginInput {
    email: String,
    password: String,
}
fn source_key(source: Option<Extension<ConnectInfo<SocketAddr>>>) -> String {
    source
        .map(|Extension(ConnectInfo(addr))| addr.ip().to_string())
        .unwrap_or_else(|| "embedded".to_owned())
}
fn session_response(state: &AppState, session: &Secret) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.session_name(), Some(session), 604800),
    );
    response
}
#[utoipa::path(post, path = "/v1/password/enroll", request_body = PasswordEnrollmentInput,
    params(("Origin" = String, Header), ("Cookie" = String, Header)),
    responses((status = 204, description = "Enrolled once; previous sessions revoked; sets replacement session cookie"),
    (status = 400, body = ErrorResponse), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse),
    (status = 413, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 429, body = ErrorResponse),
    (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
async fn enroll_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasswordEnrollmentInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let current = read_cookie(&headers, state.browser.session_name())?;
    let password = Password::parse(input.password)?;
    let session = state
        .auth
        .enroll_password(&current, password, &source_key(source))
        .await?;
    Ok(session_response(&state, &session))
}
#[utoipa::path(post, path = "/v1/password/login", request_body = PasswordLoginInput,
    params(("Origin" = String, Header)),
    responses((status = 204, description = "Sets fresh session cookie"), (status = 400, body = ErrorResponse),
    (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 413, body = ErrorResponse),
    (status = 415, body = ErrorResponse), (status = 429, body = ErrorResponse), (status = 503, body = ErrorResponse),
    (status = 504, body = ErrorResponse)))]
async fn password_login(
    State(state): State<AppState>,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasswordLoginInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let password = Password::parse(input.password).map_err(|_| Error::Unauthorized)?;
    let session = state
        .auth
        .password_login(&input.email, password, &source_key(source))
        .await?;
    Ok(session_response(&state, &session))
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct PasswordResetInput {
    token: String,
    password: String,
}
#[utoipa::path(post, path = "/v1/password/reset/start", request_body = EmailInput,
    params(("Origin" = String, Header)), responses((status = 202, body = Accepted, description = "Generic response; sets reset binding cookie; same delivery path for every email"),
    (status = 400, body = ErrorResponse), (status = 403, body = ErrorResponse), (status = 413, body = ErrorResponse),
    (status = 415, body = ErrorResponse), (status = 429, body = ErrorResponse), (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
async fn start_password_reset(
    State(state): State<AppState>,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<EmailInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = state
        .auth
        .start_password_reset(&input.email, &source_key(source))
        .await?;
    let mut response =
        (StatusCode::ACCEPTED, Json(Accepted { status: "accepted" })).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state
            .browser
            .cookie(state.browser.reset_name(), Some(&browser), 600),
    );
    Ok(response)
}
#[utoipa::path(post, path = "/v1/password/reset/finish", request_body = PasswordResetInput,
    params(("Origin" = String, Header), ("Cookie" = String, Header, description = "Reset binding cookie")),
    responses((status = 204, description = "Password replaced; all sessions and outstanding proofs invalidated; clears reset/session cookies; login required"),
    (status = 400, body = ErrorResponse), (status = 401, body = ErrorResponse), (status = 403, body = ErrorResponse),
    (status = 413, body = ErrorResponse), (status = 415, body = ErrorResponse), (status = 429, body = ErrorResponse),
    (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
async fn finish_password_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Result<Json<PasswordResetInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(input) = input.map_err(ApiError::from)?;
    let browser = read_cookie(&headers, state.browser.reset_name())?;
    state
        .auth
        .finish_password_reset(
            Secret::parse(input.token)?,
            browser,
            Password::parse(input.password)?,
            &source_key(source),
        )
        .await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    for name in [state.browser.reset_name(), state.browser.session_name()] {
        response
            .headers_mut()
            .append(header::SET_COOKIE, state.browser.cookie(name, None, 0));
    }
    Ok(response)
}
#[utoipa::path(get, path = "/v1/session", params(("Cookie" = String, Header, description = "Session cookie")),
    responses((status = 200, body = UserResponse), (status = 401, body = ErrorResponse), (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
async fn session(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let token = read_cookie(&headers, state.browser.session_name())?;
    let user = state.auth.authenticate(&token).await?;
    Ok(Json(UserResponse {
        id: user.id,
        realm_id: user.realm_id,
        email: user.email,
    })
    .into_response())
}
#[utoipa::path(post, path = "/v1/logout", params(("Origin" = String, Header), ("Cookie" = String, Header)),
    responses((status = 204, description = "Revoked and cleared session"), (status = 403, body = ErrorResponse), (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    // Missing/invalid credentials are already logged out; duplicate cookies cannot select an identity.
    if let Ok(token) = read_cookie(&headers, state.browser.session_name()) {
        state.auth.logout(&token).await?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        state.browser.cookie(state.browser.session_name(), None, 0),
    );
    Ok(response)
}
#[utoipa::path(get, path = "/readyz", responses((status = 200), (status = 503, body = ErrorResponse), (status = 504, body = ErrorResponse)))]
async fn ready(State(state): State<AppState>) -> Result<StatusCode, ApiError> {
    state.auth.ready().await?;
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_fails_closed() {
        for bad in [
            "http://example.com",
            "https://u:p@example.com",
            "https://example.com/path",
            "https://example.com/?x=1",
            "https://example.com/#x",
            "file:///tmp/x",
        ] {
            assert!(BrowserConfig::new(bad, false).is_err(), "{bad}");
        }
        assert!(BrowserConfig::new("http://example.com", true).is_err());
        assert!(BrowserConfig::new("http://127.0.0.1:8080", true).is_ok());
        let config = BrowserConfig::new("https://example.com", false).unwrap();
        let cookie = config.cookie(
            config.session_name(),
            Some(&Secret::generate().unwrap()),
            60,
        );
        let cookie = cookie.to_str().unwrap();
        for expected in ["__Host-", "Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
            assert!(cookie.contains(expected));
        }
        assert!(!cookie.contains("Domain="));
    }
    #[test]
    fn duplicate_cookies_cannot_select_a_session() {
        let token = Secret::generate().unwrap();
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            format!(
                "auth-session={}; auth-session={}",
                token.expose(),
                token.expose()
            )
            .parse()
            .unwrap(),
        );
        assert!(read_cookie(&headers, "auth-session").is_err());
    }
}

impl From<axum::extract::rejection::JsonRejection> for ApiError {
    fn from(rejection: axum::extract::rejection::JsonRejection) -> Self {
        let status = match rejection.status() {
            StatusCode::PAYLOAD_TOO_LARGE => StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::UNSUPPORTED_MEDIA_TYPE => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            _ => StatusCode::BAD_REQUEST,
        };
        Self::Body(status)
    }
}
#[derive(Serialize, ToSchema)]
struct ErrorResponse {
    code: &'static str,
}
#[derive(Serialize, ToSchema)]
struct Accepted {
    status: &'static str,
}
#[derive(Serialize, ToSchema)]
struct UserResponse {
    id: Uuid,
    realm_id: Uuid,
    email: String,
}
#[utoipa::path(get, path = "/healthz", responses((status = 200), (status = 504, body = ErrorResponse)))]
async fn health() -> StatusCode {
    StatusCode::OK
}
#[derive(OpenApi)]
#[openapi(
    info(
        title = "easy-auth",
        description = "Experimental same-origin browser API; not an OIDC issuer. POST requests require the exact configured Origin. HTTPS production cookies use __Host- prefix, Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain. Development loopback cookies omit the prefix and Secure. Auth responses are no-store."
    ),
    paths(
        health,
        ready,
        start,
        finish,
        enroll_password,
        password_login,
        start_password_reset,
        finish_password_reset,
        session,
        logout
    ),
    components(schemas(
        EmailInput,
        FinishInput,
        PasswordEnrollmentInput,
        PasswordLoginInput,
        PasswordResetInput,
        ErrorResponse,
        Accepted,
        UserResponse
    ))
)]
struct ApiDoc;
/// Generated from the implemented HTTP handlers and transport DTOs.
pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}
