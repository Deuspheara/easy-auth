use super::{attempt::Attempt, setup::Fixture, socket};
use auth_core::{GoogleAuthorizationCompletion, Result};
use easy_auth_server::GoogleDesktopCallback;
use std::{future::pending, time::Duration};

pub(super) async fn capture(
    f: &mut Fixture,
    a: &Attempt,
    error: Option<&str>,
) -> GoogleDesktopCallback {
    let listener = f.listener.take().expect("exact owned listener required");
    let uri = url::Url::parse(listener.redirect().as_str()).unwrap();
    let raw = socket::request(&uri, &a.query(error));
    let (captured, response) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            listener.receive(a.state(), a.cap, pending()),
            socket::send(&uri, &raw)
        )
    })
    .await
    .expect("test infrastructure: actual native receive before original deadline");
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(!response.contains(a.state().expose()));
    assert!(!response.contains(a.code.expose()));
    assert!(!response.contains("private-provider-detail"));
    assert!(!response.contains("set-cookie:"));
    socket::stopped(&uri).await;
    captured.expect("test infrastructure: owned positive return must be delivered")
}
pub(super) async fn finish(
    f: &Fixture,
    a: &Attempt,
    captured: GoogleDesktopCallback,
) -> Result<GoogleAuthorizationCompletion> {
    captured
        .finish(&f.service, &a.intent(), a.state(), a.proof())
        .await
}
