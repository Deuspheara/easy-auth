use super::FixtureResult;
use auth_axum::{
    BrowserConfig, OidcAccountDeletionServices, experimental_oidc_account_deletion_router,
};
use auth_core::{Auth, Secret};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{net::TcpListener, task::JoinHandle};

pub(super) struct Bootstrap {
    origin: String,
    pending: Mutex<Option<(Secret, Secret)>>,
}
impl Bootstrap {
    pub fn arm(&self, session: &Secret) -> auth_core::Result<Secret> {
        let capability = Secret::generate()?;
        *self.pending.lock().unwrap() = Some((
            Secret::parse(capability.expose().into())?,
            Secret::parse(session.expose().into())?,
        ));
        Ok(capability)
    }
}
pub(super) struct Server {
    pub address: SocketAddr,
    pub bootstrap: Arc<Bootstrap>,
    task: Option<JoinHandle<std::io::Result<()>>>,
}
impl Server {
    pub async fn new(
        auth: Auth,
        origin: &str,
        services: OidcAccountDeletionServices,
    ) -> FixtureResult<Self> {
        let app = experimental_oidc_account_deletion_router(
            auth,
            BrowserConfig::new(origin, false)?,
            services,
        )?;
        let bootstrap = Arc::new(Bootstrap {
            origin: origin.into(),
            pending: Mutex::new(None),
        });
        let fixture = Router::new()
            .route("/fixture/session", post(redeem))
            .layer(DefaultBodyLimit::max(8192))
            .with_state(bootstrap.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.merge(fixture)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        });
        Ok(Self {
            address,
            bootstrap,
            task: Some(task),
        })
    }
    pub async fn close(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    capability: String,
}
async fn redeem(
    State(state): State<Arc<Bootstrap>>,
    headers: HeaderMap,
    body: Result<Json<Input>, JsonRejection>,
) -> Response {
    let mut response = redeem_inner(&state, &headers, body);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("referrer-policy", "no-referrer".parse().unwrap());
    response
}
fn redeem_inner(
    state: &Bootstrap,
    headers: &HeaderMap,
    body: Result<Json<Input>, JsonRejection>,
) -> Response {
    if headers.get_all(header::ORIGIN).iter().count() != 1
        || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(&state.origin)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(Json(input)) = body else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(capability) = Secret::parse(input.capability) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let mut pending = state.pending.lock().unwrap();
    if pending
        .as_ref()
        .is_none_or(|(expected, _)| expected.verifier() != capability.verifier())
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (_, session) = pending.take().unwrap();
    // Fixture-only one-use delivery of the actual committed provider session. No
    // account/session is seeded; no raw session is emitted on the private IPC.
    let value = format!(
        "__Host-auth-session={}; Path=/; HttpOnly; Secure; SameSite=Lax",
        session.expose()
    );
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, value.parse().unwrap());
    response
}
