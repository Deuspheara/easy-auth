use super::{binding, cancellation, claims, pages, passkey_recovery_openapi, replacement};
use crate::{Auth, BrowserConfig, browser::boundary, router::AppState};
use auth_core::{
    Error, PasskeyEnrollment, PasskeyManagement, PasskeyRecoveryClaims, PasskeyRecoveryReplacement,
    PasskeyRecoverySetup, PasskeySignIn, PasskeySignup, Result,
};
use axum::{Router, extract::DefaultBodyLimit, middleware, routing::post};
use std::sync::Arc;
use url::Url;

/// Named aligned dependencies for explicit experimental recovery composition.
pub struct PasskeyRecoveryServices {
    pub enrollment: Arc<PasskeyEnrollment>,
    pub sign_in: Arc<PasskeySignIn>,
    pub signup: Arc<PasskeySignup>,
    pub management: Arc<PasskeyManagement>,
    pub setup: Arc<PasskeyRecoverySetup>,
    pub claims: Arc<PasskeyRecoveryClaims>,
    pub replacement: Arc<PasskeyRecoveryReplacement>,
}
#[derive(Clone)]
pub(super) struct RecoveryState {
    pub base: AppState,
    pub claims: Arc<PasskeyRecoveryClaims>,
    pub replacement: Arc<PasskeyRecoveryReplacement>,
}

/// Explicit opt-in transport. Independent recovery review and ordinary activation remain gated.
pub fn experimental_passkey_recovery_router(
    auth: Auth,
    browser: BrowserConfig,
    services: PasskeyRecoveryServices,
) -> Result<Router> {
    let origin = Url::parse(browser.origin()).map_err(|_| Error::InvalidInput)?;
    for (realm, configured_origin) in [
        (services.claims.realm(), services.claims.origin()),
        (services.replacement.realm(), services.replacement.origin()),
    ] {
        if realm != auth.realm() || configured_origin != origin.as_str() {
            return Err(Error::InvalidInput);
        }
    }
    let setup = super::super::recovery_setup::setup_routes(&auth, &browser, services.setup)?;
    let state = RecoveryState {
        base: AppState {
            auth: auth.clone(),
            browser: browser.clone(),
        },
        claims: services.claims,
        replacement: services.replacement,
    };
    let recovery = claim_routes()
        .merge(ceremony_routes())
        .merge(pages::routes())
        .layer(middleware::from_fn_with_state(state.base.clone(), boundary))
        .with_state(state);
    Ok(super::super::management::configured_management_router(
        auth,
        browser,
        services.enrollment,
        services.sign_in,
        services.signup,
        services.management,
        passkey_recovery_openapi(),
    )?
    .merge(setup)
    .merge(recovery))
}

fn claim_routes() -> Router<RecoveryState> {
    Router::new()
        .route("/v1/passkeys/recovery/browser", post(binding::bind_browser))
        .route(
            "/v1/passkeys/recovery/claims/start",
            post(claims::start_claim),
        )
        .route(
            "/v1/passkeys/recovery/claims/resume",
            post(claims::resume_claim),
        )
        .route(
            "/v1/passkeys/recovery/claims/status",
            post(claims::claim_status),
        )
        .route(
            "/v1/passkeys/recovery/claims/cancel",
            post(cancellation::cancel_browser),
        )
        .route(
            "/v1/passkeys/recovery/claims/cancel-with-code",
            post(cancellation::cancel_code),
        )
        .route(
            "/v1/passkeys/recovery/claims/cancel-with-key",
            post(cancellation::cancel_key),
        )
        .route(
            "/v1/passkeys/recovery/replacement/start",
            post(replacement::start_replacement),
        )
        .layer(DefaultBodyLimit::max(8192))
}
fn ceremony_routes() -> Router<RecoveryState> {
    Router::new()
        .route(
            "/v1/passkeys/recovery/replacement/registration",
            post(replacement::verify_registration),
        )
        .route(
            "/v1/passkeys/recovery/replacement/finish",
            post(replacement::complete_recovery),
        )
        .layer(DefaultBodyLimit::max(32 * 1024))
}
