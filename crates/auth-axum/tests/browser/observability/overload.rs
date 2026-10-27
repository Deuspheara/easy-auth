//! Real HTTP/KDF pressure with a controlled blocking worker, not timing guesses.
use super::capture::Capture;
use crate::support::{Mail, post};
use auth_core::{Auth, Error, Password, PasswordService};
use auth_postgres::Postgres;
use axum::{Router, http::StatusCode};
use easy_auth_axum::BrowserConfig;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{sync::Arc, time::Duration};
use tokio::task::JoinSet;
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;
use uuid::Uuid;

#[sqlx::test]
async fn http_hash_overload_stays_bounded_after_cancellation_and_recovers(pool: PgPool) {
    let options = pool.connect_options();
    pool.close().await;
    // Control the blocking queue in a private runtime. The SQLx test's outer
    // runtime remains live and owns the disposable database's final cleanup.
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let pool = PgPoolOptions::new()
                    .max_connections(4)
                    .connect_with((*options).clone())
                    .await
                    .unwrap();
                let (app, passwords) = application(pool.clone()).await;
                exercise(app, passwords).await;
                pool.close().await;
            });
    })
    .await
    .unwrap();
}

async fn application(pool: PgPool) -> (Router, Arc<PasswordService>) {
    let store = Postgres::new(pool);
    store.migrate().await.unwrap();
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    let passwords = Arc::new(PasswordService::new("a compromised example password").unwrap());
    let auth = Auth::new(realm, Arc::new(store), Arc::new(Mail::default()))
        .with_passwords(passwords.clone());
    (
        easy_auth_axum::router(
            auth,
            BrowserConfig::new("https://app.example", false).unwrap(),
        ),
        passwords,
    )
}

async fn exercise(app: Router, passwords: Arc<PasswordService>) {
    let capture = Capture::default();
    let (release, receiver) = std::sync::mpsc::channel::<()>();
    let (started, ready) = tokio::sync::oneshot::channel();
    let blocker = tokio::task::spawn_blocking(move || {
        started.send(()).unwrap();
        // Dropping release on any panic frees this worker; never strand runtime
        // shutdown or weaken production hash parameters to make the case faster.
        let _ = receiver.recv_timeout(Duration::from_secs(30));
    });
    ready.await.unwrap();
    let mut requests = JoinSet::new();
    for index in 0..32 {
        requests.spawn(
            app.clone()
                .oneshot(login(index))
                .with_subscriber(capture.dispatcher()),
        );
    }
    let first = tokio::time::timeout(Duration::from_secs(10), requests.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .unwrap();
    // All identities are unknown and have separate email budgets; 32 attempts
    // are below the shared 40/source window. Only KDF saturation can refuse now.
    assert_eq!(first.status(), StatusCode::TOO_MANY_REQUESTS);
    requests.abort_all();
    while let Some(result) = requests.join_next().await {
        match result {
            Ok(Ok(response)) => assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS),
            Err(error) => assert!(error.is_cancelled()),
            _ => panic!("unexpected HTTP pressure failure"),
        }
    }
    let response = app
        .clone()
        .oneshot(login(32))
        .with_subscriber(capture.dispatcher())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        capture
            .events()
            .iter()
            .any(|event| event["completion"] == "cancelled")
    );
    drop(release);
    blocker.await.unwrap();
    wait_for_hash_capacity(&passwords).await;
    let response = app
        .oneshot(login(33))
        .with_subscriber(capture.dispatcher())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let events = capture.events();
    assert!(
        events
            .iter()
            .any(|event| event.get("status") == Some(&serde_json::json!(429)))
    );
    assert!(
        events
            .iter()
            .any(|event| event.get("status") == Some(&serde_json::json!(401)))
    );
    for event in events {
        assert!(event["duration_micros"].as_u64().is_some());
        assert!(Uuid::parse_str(event["request_id"].as_str().unwrap()).is_ok());
    }
}

fn login(index: usize) -> axum::http::Request<axum::body::Body> {
    post(
        "/v1/password/login",
        &serde_json::json!({
            "email": format!("pressure-{index}@example.test"),
            "password": "synthetic pressure input phrase",
        })
        .to_string(),
        None,
        Some("https://app.example"),
    )
}

async fn wait_for_hash_capacity(passwords: &PasswordService) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match passwords
                .verify(
                    Password::parse("synthetic pressure input phrase".into()).unwrap(),
                    None,
                )
                .await
            {
                Ok(false) => break,
                Err(Error::RateLimited) => tokio::time::sleep(Duration::from_millis(10)).await,
                _ => panic!("cancelled hash jobs did not release capacity safely"),
            }
        }
    })
    .await
    .expect("cancelled hash jobs did not finish within the fixture bound");
}
