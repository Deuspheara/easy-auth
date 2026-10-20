use super::{GoogleDesktopCallback, GoogleDesktopError, http};
use auth_core::{OAuthRedirect, Secret};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;

const MAX_CALLBACK_WAIT: Duration = Duration::from_secs(300);
const MAX_CONNECTIONS: usize = 8;

/// A concrete exclusively owned desktop loopback socket, bound before authorization.
/// Explicit opt-in transport; no mobile fallback, browser launch or login activation.
pub struct GoogleDesktopListener {
    listener: TcpListener,
    redirect: OAuthRedirect,
    authority: String,
    path: String,
}
impl GoogleDesktopListener {
    pub async fn bind(ip: IpAddr, path: &str) -> Result<Self, GoogleDesktopError> {
        if ip != IpAddr::V4(Ipv4Addr::LOCALHOST) && ip != IpAddr::V6(Ipv6Addr::LOCALHOST) {
            return Err(GoogleDesktopError::InvalidInput);
        }
        let listener = TcpListener::bind(SocketAddr::new(ip, 0))
            .await
            .map_err(|_| GoogleDesktopError::Unavailable)?;
        let address = listener
            .local_addr()
            .map_err(|_| GoogleDesktopError::Unavailable)?;
        let redirect = OAuthRedirect::desktop_loopback(address, path)
            .map_err(|_| GoogleDesktopError::InvalidInput)?;
        Ok(Self {
            listener,
            redirect,
            authority: address.to_string(),
            path: path.to_owned(),
        })
    }

    /// Persist this exact redirect/revision before constructing the Google flow.
    /// Retain this listener until receive completes or it is explicitly dropped.
    pub fn redirect(&self) -> &OAuthRedirect {
        &self.redirect
    }

    /// Resource lifetime uses the original expiry, capped at five minutes. It is
    /// not database authority; shared core/PostgreSQL still recheck original caps.
    /// Cancelling/dropping closes socket/stream, but does not cancel database state:
    /// the caller must separately use GoogleAuthorization::cancel with its proof.
    pub async fn receive(
        self,
        state: &Secret,
        expires_us: i64,
        cancel: impl Future<Output = ()>,
    ) -> Result<GoogleDesktopCallback, GoogleDesktopError> {
        let remaining = remaining(expires_us)?;
        tokio::select! {
            biased;
            _ = cancel => Err(GoogleDesktopError::Cancelled),
            _ = tokio::time::sleep(remaining) => Err(GoogleDesktopError::Expired),
            response = self.receive_inner(state) => response,
        }
    }

    async fn receive_inner(
        self,
        state: &Secret,
    ) -> Result<GoogleDesktopCallback, GoogleDesktopError> {
        let target = Arc::new(http::Target {
            authority: self.authority,
            path: self.path,
            state: state.verifier(),
        });
        // Sequential bounded connections avoid detached tasks or unbounded queues.
        // An invalid/slow local request spends one slot but mutates no auth state.
        for _ in 0..MAX_CONNECTIONS {
            let (stream, peer) = self
                .listener
                .accept()
                .await
                .map_err(|_| GoogleDesktopError::Unavailable)?;
            if !peer.ip().is_loopback() {
                continue;
            }
            if let Some(response) = http::receive(stream, target.clone()).await? {
                return Ok(GoogleDesktopCallback::received(
                    response,
                    self.redirect.as_str().to_owned(),
                ));
            }
        }
        Err(GoogleDesktopError::RequestLimit)
    }
}

fn remaining(expires_us: i64) -> Result<Duration, GoogleDesktopError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GoogleDesktopError::Unavailable)?
        .as_micros();
    let now = i64::try_from(now).map_err(|_| GoogleDesktopError::Unavailable)?;
    let remaining = expires_us
        .checked_sub(now)
        .filter(|value| *value > 0)
        .ok_or(GoogleDesktopError::Expired)?;
    Ok(Duration::from_micros(remaining as u64).min(MAX_CALLBACK_WAIT))
}
