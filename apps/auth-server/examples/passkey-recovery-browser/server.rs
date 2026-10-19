use auth_axum::{PasskeyRecoveryServices, experimental_passkey_recovery_router};
use auth_core::{
    PasskeyEnrollment, PasskeyManagement, PasskeyRecoveryClaims, PasskeyRecoveryReplacement,
    PasskeyRecoverySetup, PasskeyService, PasskeySignIn, PasskeySignup, PasswordService,
};
use auth_postgres::Postgres;
use sqlx::postgres::PgPoolOptions;
use std::{error::Error, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

pub(super) async fn serve() -> Result<(), Box<dyn Error>> {
    let url = url::Url::parse(&std::env::var("DATABASE_URL")?)?;
    super::database::require_loopback(&url)?;
    if !url.path().starts_with("/easy_auth_smtp_")
        || std::env::var("AUTH_DEVELOPMENT")?.as_str() != "true"
    {
        return Err("owned development database required".into());
    }
    let (auth, browser, bind) = easy_auth_server::configured_auth().await?;
    let auth = auth.with_passwords(Arc::new(PasswordService::new(
        "a compromised fixture password",
    )?));
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(url.as_str())
        .await?;
    let store = Arc::new(Postgres::new(pool.clone()));
    let service = Arc::new(PasskeyService::for_local_development(
        browser.origin(),
        "Recovery browser fixture",
    )?);
    let realm = auth.realm();
    let services = PasskeyRecoveryServices {
        enrollment: Arc::new(PasskeyEnrollment::new(
            realm,
            service.clone(),
            store.clone(),
        )),
        sign_in: Arc::new(PasskeySignIn::new(realm, service.clone(), store.clone())),
        signup: Arc::new(PasskeySignup::new(realm, service.clone(), store.clone())),
        management: Arc::new(PasskeyManagement::new(
            realm,
            service.clone(),
            store.clone(),
        )),
        setup: Arc::new(PasskeyRecoverySetup::new(
            realm,
            service.clone(),
            store.clone(),
        )),
        claims: Arc::new(PasskeyRecoveryClaims::new(
            realm,
            service.clone(),
            store.clone(),
        )),
        replacement: Arc::new(PasskeyRecoveryReplacement::new(
            realm,
            service.clone(),
            store,
        )),
    };
    let notifications = easy_auth_server::notification_worker(auth.clone());
    let app = experimental_passkey_recovery_router(auth, browser.clone(), services)?;
    let listener = TcpListener::bind(bind).await?;
    super::clock::listen(pool, realm, service.rp_id().to_owned());
    println!("{}", serde_json::json!({"origin":browser.origin()}));
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    notifications.abort();
    Ok(())
}
