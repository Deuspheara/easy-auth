use super::GoogleDesktopError;
use auth_core::{GoogleAuthorizationResponse, Verifier};
use axum::body::{Body, HttpBody};
use hyper::{Request, Response, StatusCode, Version, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpStream;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);
const HEADER_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 32;

pub(super) struct Target {
    pub authority: String,
    pub path: String,
    pub state: Verifier,
}

pub(super) async fn receive(
    stream: TcpStream,
    target: Arc<Target>,
) -> Result<Option<GoogleAuthorizationResponse>, GoogleDesktopError> {
    let received = Arc::new(Mutex::new(None));
    let slot = received.clone();
    let service = service_fn(move |request: Request<Incoming>| {
        let response = validate(&request, &target);
        let status = match response {
            Some(response) => match slot.lock() {
                Ok(mut slot) => {
                    *slot = Some(response);
                    StatusCode::OK
                }
                Err(_) => StatusCode::SERVICE_UNAVAILABLE,
            },
            None => StatusCode::BAD_REQUEST,
        };
        async move { Ok::<_, Infallible>(page(status)) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .keep_alive(false)
        .max_headers(MAX_HEADERS)
        .max_buf_size(MAX_HEADER_BYTES)
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT);
    // The connection future owns its stream; no connection task outlives receive.
    // A disconnect after valid delivery does not undo that delivery or grant auth.
    let _ = tokio::time::timeout(
        CONNECTION_TIMEOUT,
        builder.serve_connection(TokioIo::new(stream), service),
    )
    .await;
    received
        .lock()
        .map_err(|_| GoogleDesktopError::Unavailable)
        .map(|mut slot| slot.take())
}

fn validate(request: &Request<Incoming>, target: &Target) -> Option<GoogleAuthorizationResponse> {
    if request.method() != hyper::Method::GET
        || request.version() != Version::HTTP_11
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().path() != target.path
        || !request.body().is_end_stream()
        || request.headers().contains_key("transfer-encoding")
    {
        return None;
    }
    let mut hosts = request.headers().get_all("host").iter();
    if hosts.next()?.to_str().ok()? != target.authority || hosts.next().is_some() {
        return None;
    }
    if request
        .headers()
        .get("content-length")
        .is_some_and(|value| value != "0")
    {
        return None;
    }
    let response = GoogleAuthorizationResponse::parse(request.uri().query()?).ok()?;
    (response.state().verifier() == target.state).then_some(response)
}

fn page(status: StatusCode) -> Response<Body> {
    Response::builder().status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer")
        .header("x-content-type-options", "nosniff")
        .header("x-frame-options", "DENY")
        .header("cross-origin-opener-policy", "same-origin")
        .header("content-security-policy", "default-src 'none'; script-src 'sha256-ixzo+owSEfJWq9z0HJaxCJAlk3mRYZRq9JaxhZ3hBmA='; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        .header("connection", "close")
        .body(Body::from("<!doctype html><meta charset=utf-8><title>Desktop return</title><script>history.replaceState(null, \"\", location.pathname);</script><p>Continue in the application to check the result.</p>"))
        .expect("fixed desktop response headers are valid")
}
