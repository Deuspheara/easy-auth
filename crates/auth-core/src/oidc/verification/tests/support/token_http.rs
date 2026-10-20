use super::Fixture;
use crate::{Error, OidcTarget, OidcTokenHttp, OidcTokenRequest, OidcTokenResponse, Result};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::sync::Notify;
use zeroize::Zeroizing;

pub(in crate::oidc::verification::tests) struct Seen {
    pub url: String,
    pub form: Zeroizing<String>,
    pub authorization: Option<Zeroizing<String>>,
}
pub(in crate::oidc::verification::tests) struct Http {
    pub body: Mutex<Vec<u8>>,
    pub status: AtomicUsize,
    pub content_type: Mutex<String>,
    pub encoding: Mutex<Option<String>>,
    pub seen: Mutex<Vec<Seen>>,
    pub hold: AtomicBool,
    pub fail: AtomicBool,
    pub entered: Notify,
    pub release: Notify,
}
impl Http {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            body: Mutex::new(Vec::new()),
            status: AtomicUsize::new(200),
            content_type: Mutex::new("application/json".into()),
            encoding: Mutex::new(None),
            seen: Mutex::new(Vec::new()),
            hold: AtomicBool::new(false),
            fail: AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        })
    }
    pub fn success(&self, f: &Fixture, claims: &Value) {
        *self.body.lock().unwrap()=serde_json::to_vec(&json!({"id_token":f.key.raw(&serde_json::to_vec(claims).unwrap()),"access_token":"unused","token_type":"Bearer","expires_in":60})).unwrap();
    }
    pub fn posts(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}
#[async_trait]
impl OidcTokenHttp for Http {
    async fn post(
        &self,
        target: &OidcTarget,
        request: &OidcTokenRequest,
    ) -> Result<OidcTokenResponse> {
        assert_eq!(target.addresses(), ["8.8.8.8:443".parse().unwrap()]);
        self.seen.lock().unwrap().push(Seen {
            url: target.url().as_str().to_owned(),
            form: Zeroizing::new(request.form().to_owned()),
            authorization: request
                .authorization()
                .map(|v| Zeroizing::new(v.to_owned())),
        });
        if self.hold.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error::Unavailable);
        }
        OidcTokenResponse::new(
            self.status.load(Ordering::SeqCst) as u16,
            Some(self.content_type.lock().unwrap().clone()),
            self.encoding.lock().unwrap().clone(),
            self.body.lock().unwrap().clone(),
        )
    }
}
