use super::*;
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicUsize};

pub(super) struct Http {
    provider: Arc<crate::apple_provider::Provider>,
    pub failure: AtomicBool,
    pub calls: AtomicUsize,
}
impl Http {
    pub fn new(f: &Fixture) -> Arc<Self> {
        Arc::new(Self {
            provider: f.apple.clone(),
            failure: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        })
    }
}
#[async_trait]
impl AppleRevocationHttp for Http {
    async fn revoke(
        &self,
        target: &OidcTarget,
        request: &AppleRevocationRequest,
    ) -> Result<AppleRevocationResponse> {
        assert_eq!(
            target.url().as_str(),
            "https://appleid.apple.com/auth/revoke"
        );
        assert_eq!(target.addresses(), ["8.8.8.8:443".parse().unwrap()]);
        let form: Vec<_> = url::form_urlencoded::parse(request.form().as_bytes()).collect();
        assert_eq!(form.len(), 4);
        let field = |name: &str| {
            let values: Vec<_> = form.iter().filter(|(key, _)| key == name).collect();
            assert_eq!(values.len(), 1);
            values[0].1.as_ref()
        };
        assert_eq!(field("client_id"), crate::apple_provider::CLIENT);
        assert!(field("token") == "unused-owned-refresh");
        assert_eq!(field("token_type_hint"), "refresh_token");
        self.provider.assert_client_secret(field("client_secret"));
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.failure.load(Ordering::SeqCst) {
            AppleRevocationResponse::new(
                400,
                Some("application/json".into()),
                None,
                br#"{"error":"invalid_client"}"#.to_vec(),
            )
        } else {
            AppleRevocationResponse::new(200, None, None, vec![])
        }
    }
}
pub(super) fn create(
    f: &Fixture,
    vault: Arc<AppleGrantVault>,
    http: Arc<Http>,
) -> AppleGrantRevoker {
    AppleGrantRevoker::new(
        f.apple_policy.configuration().clone(),
        f.store.clone(),
        f.apple_signer.clone(),
        vault,
        f.store.clone(),
        f.apple.clone(),
        http,
    )
    .unwrap()
}
