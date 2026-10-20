use super::{ProbeResult, completion, errors, observations, settings::Settings, setup::Setup};
use easy_auth_server::{GoogleDesktopSignIn, OidcHttps};
use serde_json::Value;
use sqlx::PgPool;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub(super) async fn check_setup(pool: &PgPool, settings: Settings) -> ProbeResult<Value> {
    let profile = settings.profile.name();
    let ip = settings.ip.to_string();
    let https = Arc::new(OidcHttps::new());
    let setup = Setup::new(pool, settings, https.clone(), https).await?;
    let realm = setup.policy.configuration().realm();
    let operation = GoogleDesktopSignIn::begin(
        setup.listener,
        setup.service,
        "registered-native-setup-check",
    )
    .await
    .map_err(errors::operation)?;
    if observations::read(pool, realm).await? != (0, 0, 0, 0, 1, 0) {
        return Err("unexpected_pending_setup_facts");
    }
    operation.cancel().await.map_err(errors::local)?;
    if observations::read(pool, realm).await? != (0, 0, 0, 0, 0, 0) {
        return Err("unexpected_cancelled_setup_facts");
    }
    Ok(
        serde_json::json!({"status":"owned_setup_checked","claims_profile":profile,"loopback":ip,
        "registered_client_confirmed":false,"browser_launched":false,"credentials_submitted":false,
        "pending_cancelled":true,"users":0,"identities":0,"sessions":0,"audits":0,"pending":0}),
    )
}

pub(super) async fn run(pool: &PgPool, settings: Settings) -> ProbeResult<Value> {
    let profile = settings.profile.name();
    let ip = settings.ip.to_string();
    let https = Arc::new(OidcHttps::new());
    let setup = Setup::new(pool, settings, https.clone(), https).await?;
    let mut operation = GoogleDesktopSignIn::begin(
        setup.listener,
        setup.service,
        "registered-native-acceptance",
    )
    .await
    .map_err(errors::operation)?;
    let signal_failed = AtomicBool::new(false);
    let cancellation = async {
        if tokio::signal::ctrl_c().await.is_err() {
            signal_failed.store(true, Ordering::SeqCst);
        }
    };
    let result = operation.run(cancellation).await;
    if signal_failed.load(Ordering::SeqCst) {
        return Err("cancellation_signal_unavailable");
    }
    let completion = result.map_err(errors::operation)?;
    let mut report = completion::commit(pool, &setup.store, &setup.policy, completion).await?;
    report["claims_profile"] = profile.into();
    report["loopback"] = ip.into();
    // Original pending rows, including interrupted token I/O, are removed when the
    // caller closes its exclusively owned database; no ambient session is revoked.
    Ok(report)
}
