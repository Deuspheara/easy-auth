use super::{capture::Capture, locks};
use crate::support::*;
use axum::http::StatusCode;
use sqlx::PgPool;
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;

#[sqlx::test]
async fn database_blocked_http_timeout_is_observed_without_challenge_or_mail_commit(pool: PgPool) {
    let (app, mail) = app(pool.clone()).await;
    let capture = Capture::default();
    let mut locker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_rate_buckets IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *locker)
        .await
        .unwrap();
    let task = tokio::spawn(
        app.oneshot(post(
            "/v1/email/start",
            r#"{"email":"timeout@example.test"}"#,
            None,
            Some("https://app.example"),
        ))
        .with_subscriber(capture.dispatcher()),
    );
    locks::wait(&pool, true).await;
    let response = task.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let events = capture.events();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0]["request_id"],
        response.headers()["x-request-id"].to_str().unwrap()
    );
    assert_eq!(events[0]["completion"], "timed_out");
    assert_eq!(events[0]["status"], 504);
    assert_eq!(events[0]["message"], "http_request_completed");
    assert!(events[0]["duration_micros"].as_u64().unwrap() > 0);
    locker.rollback().await.unwrap();
    locks::drained(&pool).await;
    assert!(mail.sign_ins.lock().unwrap().is_empty());
}

#[sqlx::test]
async fn dropped_http_future_records_cancellation_in_original_subscriber_and_rolls_back(
    pool: PgPool,
) {
    let (app, mail) = app(pool.clone()).await;
    let capture = Capture::default();
    let mut locker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_rate_buckets IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *locker)
        .await
        .unwrap();
    let task = tokio::spawn(
        app.oneshot(post(
            "/v1/email/start",
            r#"{"email":"cancelled@example.test"}"#,
            None,
            Some("https://app.example"),
        ))
        .with_subscriber(capture.dispatcher()),
    );
    locks::wait(&pool, true).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let events = capture.events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    let mut keys: Vec<_> = event.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["completion", "duration_micros", "message", "request_id"]
    );
    assert_eq!(event["completion"], "cancelled");
    assert_eq!(event["message"], "http_request_cancelled");
    assert!(uuid::Uuid::parse_str(event["request_id"].as_str().unwrap()).is_ok());
    assert!(event["duration_micros"].as_u64().unwrap() > 0);
    locker.rollback().await.unwrap();
    locks::drained(&pool).await;
    assert!(mail.sign_ins.lock().unwrap().is_empty());
}
