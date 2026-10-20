use super::*;
use crate::{Error, Result, Secret};
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use uuid::Uuid;

struct Legacy(AtomicUsize);
#[async_trait]
impl OAuthTransactionRepository for Legacy {
    async fn save_oauth(&self, _: &OAuthRequest) -> Result<i64> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::Unavailable)
    }
    async fn consume_oauth(&self, _: &OAuthRequest) -> Result<i64> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::Unavailable)
    }
    async fn cancel_oauth(&self, _: &OAuthRequest) -> Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::Unavailable)
    }
}

#[tokio::test]
async fn legacy_backend_never_silently_replaces_a_requested_native_return_with_the_anchor() {
    let anchor =
        OAuthRedirect::desktop_loopback("127.0.0.1:49153".parse().unwrap(), "/owned").unwrap();
    let exact = OAuthConnection::with_redirect(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        "https://issuer.example",
        "desktop-client",
        anchor.clone(),
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    let backend = Arc::new(Legacy(AtomicUsize::new(0)));
    assert!(matches!(
        OAuthTransactions::for_desktop_return(exact.clone(), backend.clone(), anchor),
        Err(Error::InvalidInput)
    ));
    let profile = exact.with_desktop_loopback_returns().unwrap();
    let changed =
        OAuthRedirect::desktop_loopback("127.0.0.1:49154".parse().unwrap(), "/owned").unwrap();
    let flow =
        OAuthTransactions::for_desktop_return(profile.clone(), backend.clone(), changed).unwrap();
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "legacy-backend",
        purpose: OAuthPurpose::SignIn,
    };
    assert!(matches!(
        flow.begin(&intent).await,
        Err(Error::InvalidInput)
    ));
    let state = Secret::generate().unwrap();
    let proof = OAuthBrowserProof::generate().unwrap();
    assert!(matches!(
        flow.cancel(&intent, &state, &proof).await,
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        flow.consume(
            &intent,
            &state,
            proof,
            OAuthCallback {
                redirect: flow.redirect(),
                issuer: Some(profile.issuer())
            }
        )
        .await,
        Err(Error::InvalidInput)
    ));
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    let legacy_exact = OAuthTransactions::new(profile, backend.clone());
    assert!(matches!(
        legacy_exact.begin(&intent).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        backend.0.load(Ordering::SeqCst),
        1,
        "exact return still delegates to existing backend"
    );
}
