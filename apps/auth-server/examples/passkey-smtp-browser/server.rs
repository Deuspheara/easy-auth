use auth_core::{PasskeyEnrollment, PasskeyService, PasskeySignIn, PasskeySignup, PasswordService};
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
    // This is the real server composition and private SMTP adapter. Do not replace
    // delivery with a capture/no-op transport or expose private production internals.
    let (auth, browser, bind) = easy_auth_server::configured_auth().await?;
    let auth = auth.with_passwords(Arc::new(PasswordService::new(
        "a compromised fixture password",
    )?));
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(url.as_str())
        .await?;
    let store = Arc::new(Postgres::new(pool));
    let service = Arc::new(PasskeyService::for_local_development(
        browser.origin(),
        "SMTP browser fixture",
    )?);
    let enrollment = Arc::new(PasskeyEnrollment::new(
        auth.realm(),
        service.clone(),
        store.clone(),
    ));
    let sign_in = Arc::new(PasskeySignIn::new(
        auth.realm(),
        service.clone(),
        store.clone(),
    ));
    let signup = Arc::new(PasskeySignup::new(auth.realm(), service, store));
    let app = auth_axum::experimental_passkey_signup_router(
        auth,
        browser.clone(),
        enrollment,
        sign_in,
        signup,
    )?;
    let listener = TcpListener::bind(bind).await?;
    println!("{}", serde_json::json!({"origin":browser.origin()}));
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
