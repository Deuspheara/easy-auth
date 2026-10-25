use super::super::super::provider::{CLIENT, Provider};
pub(super) use super::super::super::setup::Fixture;
pub(super) use super::super::*;
use async_trait::async_trait;
use std::sync::Mutex;
pub(super) use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;
#[derive(Clone, Copy)]
pub(super) enum Mode {
    Success,
    Transport,
    InvalidClient,
    InvalidGrant,
    FalseSuccess,
    Compressed,
    Hold,
    LostResponse,
}
pub(super) struct Http {
    provider: Arc<Provider>,
    pub mode: Mutex<Mode>,
    pub calls: AtomicUsize,
    pub applied: AtomicUsize,
    pub entered: Notify,
    pub release: Notify,
}
impl Http {
    pub fn new(f: &Fixture) -> Arc<Self> {
        Arc::new(Self {
            provider: f.provider.clone(),
            mode: Mutex::new(Mode::Success),
            calls: AtomicUsize::new(0),
            applied: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Notify::new(),
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
        assert_eq!(format!("{request:?}"), "AppleRevocationRequest([REDACTED])");
        let pairs: Vec<_> = url::form_urlencoded::parse(request.form().as_bytes()).collect();
        assert_eq!(pairs.len(), 4);
        let value = |name: &str| {
            let values: Vec<_> = pairs.iter().filter(|(k, _)| k == name).collect();
            assert_eq!(values.len(), 1);
            values[0].1.as_ref()
        };
        assert!(value("client_id") == CLIENT);
        assert!(value("token_type_hint") == "refresh_token");
        assert!(value("token") == "unused-owned-refresh");
        self.provider.assert_client_secret(value("client_secret"));
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mode = *self.mode.lock().unwrap();
        match mode {
            Mode::Transport => Err(Error::Unavailable),
            Mode::InvalidClient => AppleRevocationResponse::new(
                400,
                Some("application/json".into()),
                None,
                br#"{"error":"invalid_client","error_description":"private-fixture-detail"}"#
                    .to_vec(),
            ),
            Mode::InvalidGrant => AppleRevocationResponse::new(
                400,
                Some("application/json".into()),
                None,
                br#"{"error":"invalid_grant"}"#.to_vec(),
            ),
            Mode::FalseSuccess => AppleRevocationResponse::new(
                200,
                Some("application/json".into()),
                None,
                br#"{"error":"invalid_client"}"#.to_vec(),
            ),
            Mode::Compressed => {
                AppleRevocationResponse::new(200, None, Some("gzip".into()), vec![])
            }
            Mode::Success | Mode::Hold | Mode::LostResponse => {
                self.applied.fetch_add(1, Ordering::SeqCst);
                if matches!(mode, Mode::Hold) {
                    self.entered.notify_one();
                    self.release.notified().await;
                }
                if matches!(mode, Mode::LostResponse) {
                    return Err(Error::Unavailable);
                }
                AppleRevocationResponse::new(200, None, None, vec![])
            }
        }
    }
}
pub(super) fn worker(f: &Fixture, http: Arc<Http>) -> AppleGrantRevoker {
    AppleGrantRevoker::new(
        f.policy.configuration().clone(),
        f.store.clone(),
        f.signer.clone(),
        f.vault.clone(),
        f.store.clone(),
        f.provider.clone(),
        http,
    )
    .unwrap()
}
pub(super) async fn pending(f: &Fixture) -> (User, Secret, Uuid) {
    let (owner, current) = local(f).await;
    let id = link(f, &owner, &current, "revoked-source").await.id;
    OidcIdentityLinking::new(f.store.clone())
        .unlink(f.realm(), &current, id)
        .await
        .unwrap();
    let grant: Uuid = sqlx::query_scalar("SELECT id FROM auth_apple_grants WHERE realm_id=$1")
        .bind(f.realm())
        .fetch_one(&f.pool)
        .await
        .unwrap();
    (owner, current, grant)
}
pub(super) async fn state(f: &Fixture) -> (String, i32, Option<String>, bool) {
    sqlx::query_as("SELECT state,attempts,failure,ciphertext IS NULL AND key_id IS NULL FROM auth_apple_grants WHERE realm_id=$1")
        .bind(f.realm()).fetch_one(&f.pool).await.unwrap()
}

pub(super) async fn leased(f: &Fixture) -> AppleGrantRevocationJob {
    use sqlx::Row;
    let row=sqlx::query("SELECT lease_id,version,(extract(epoch FROM lease_until)*1000000)::bigint AS until_us FROM auth_apple_grants WHERE realm_id=$1 AND state='leased'")
        .bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    let envelope = envelopes(f).await.pop().unwrap();
    let until: i64 = row.get("until_us");
    AppleGrantRevocationJob::restore(
        envelope,
        row.get("lease_id"),
        row.get("version"),
        until - 60_000_000,
        until,
    )
    .unwrap()
}
pub(super) async fn wait_clock(pool: &sqlx::PgPool, cap: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(65), async {
        loop {
            let expired: bool = sqlx::query_scalar(
                "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint >= $1",
            )
            .bind(cap)
            .fetch_one(pool)
            .await
            .unwrap();
            if expired {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("owned database deadline observed within its configured interval");
}
