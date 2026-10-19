use super::mail::DisabledMail;
use auth_core::{Auth, PasskeyEnrollment, PasskeyService, Repository, Secret};
use auth_postgres::Postgres;
use easy_auth_axum::{BrowserConfig, experimental_passkey_enrollment_router};
use sqlx::postgres::PgPoolOptions;
use std::{error::Error, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use uuid::Uuid;

pub(super) async fn serve(url: &str, sessions: Vec<String>) -> Result<(), Box<dyn Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await?;
    let result = run(pool.clone(), sessions).await;
    pool.close().await;
    result
}

async fn run(pool: sqlx::PgPool, sessions: Vec<String>) -> Result<(), Box<dyn Error>> {
    let store = Arc::new(Postgres::new(pool.clone()));
    store.migrate().await?;
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await?;
    for (index, session) in sessions.into_iter().enumerate() {
        let token = Secret::generate()?;
        let browser = Secret::generate()?;
        let email = format!("browser-{index}@example.test");
        store
            .begin_email(realm, &email, token.verifier(), browser.verifier(), [1; 32])
            .await?;
        store
            .finish_email(
                realm,
                token.verifier(),
                browser.verifier(),
                Secret::parse(session)?.verifier(),
            )
            .await?;
    }
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://localhost:{}", listener.local_addr()?.port());
    let browser = BrowserConfig::new(&origin, true)?;
    let service = Arc::new(PasskeyService::for_local_development(
        &origin,
        "Browser fixture",
    )?);
    let enrollment = Arc::new(PasskeyEnrollment::new(realm, service, store.clone()));
    let app = experimental_passkey_enrollment_router(
        Auth::new(realm, store, Arc::new(DisabledMail)),
        browser,
        enrollment,
    )?;
    println!("{}", serde_json::json!({"origin":origin}));
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    let credentials: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys")
        .fetch_one(&pool)
        .await?;
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='passkey_enrolled'")
            .fetch_one(&pool)
            .await?;
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkey_enrollments")
        .fetch_one(&pool)
        .await?;
    let postgres_version: String = sqlx::query_scalar("SELECT current_setting('server_version')")
        .fetch_one(&pool)
        .await?;
    println!(
        "{}",
        serde_json::json!({"credentials":credentials,"audits":audits,"pending":pending,"postgres_version":postgres_version})
    );
    Ok(())
}
