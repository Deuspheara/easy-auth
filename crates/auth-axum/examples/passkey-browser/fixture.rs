use super::mail::DisabledMail;
use auth_core::{Auth, PasskeyEnrollment, PasskeyService, PasskeySignIn, Repository, Secret};
use auth_postgres::Postgres;
use easy_auth_axum::{BrowserConfig, experimental_passkey_router};
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
    let mut owners = Vec::new();
    for (index, session) in sessions.into_iter().enumerate() {
        let token = Secret::generate()?;
        let browser = Secret::generate()?;
        let email = format!("browser-{index}@example.test");
        store
            .begin_email(realm, &email, token.verifier(), browser.verifier(), [1; 32])
            .await?;
        let user = store
            .finish_email(
                realm,
                token.verifier(),
                browser.verifier(),
                Secret::parse(session)?.verifier(),
            )
            .await?;
        owners.push(user.id);
    }
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://localhost:{}", listener.local_addr()?.port());
    let browser = BrowserConfig::new(&origin, true)?;
    let service = Arc::new(PasskeyService::for_local_development(
        &origin,
        "Browser fixture",
    )?);
    let enrollment = Arc::new(PasskeyEnrollment::new(
        realm,
        service.clone(),
        store.clone(),
    ));
    let sign_in = Arc::new(PasskeySignIn::new(realm, service, store.clone()));
    let app = experimental_passkey_router(
        Auth::new(realm, store, Arc::new(DisabledMail)),
        browser,
        enrollment,
        sign_in,
    )?;
    super::counterless::listen(pool.clone(), realm, *owners.last().ok_or("empty fixture")?);
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
    let authentication_audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='passkey_authenticated'")
            .fetch_one(&pool)
            .await?;
    let passkey_sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_sessions WHERE authentication_method='passkey'",
    )
    .fetch_one(&pool)
    .await?;
    let authentication_pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_passkey_authentications")
            .fetch_one(&pool)
            .await?;
    let authentication_finish_attempts:i64=sqlx::query_scalar("SELECT coalesce(sum(attempts),0)::bigint FROM auth_rate_buckets WHERE dimension='passkey_auth_finish_source'").fetch_one(&pool).await?;
    let backed_up_credentials: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE last_used_at IS NOT NULL AND convert_from(credential,'UTF8')::jsonb #>> '{cred,backup_state}'='true'").fetch_one(&pool).await?;
    let zero_counter_credentials: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE last_used_at IS NOT NULL AND convert_from(credential,'UTF8')::jsonb #>> '{cred,counter}'='0'").fetch_one(&pool).await?;
    println!(
        "{}",
        serde_json::json!({"credentials":credentials,"audits":audits,"pending":pending,"postgres_version":postgres_version,
            "authentication_audits":authentication_audits,"passkey_sessions":passkey_sessions,
            "authentication_pending":authentication_pending,"backed_up_credentials":backed_up_credentials,
            "authentication_finish_attempts":authentication_finish_attempts,
            "zero_counter_credentials":zero_counter_credentials})
    );
    Ok(())
}
