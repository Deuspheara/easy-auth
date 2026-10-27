use super::capture::Capture;
use crate::support::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::PgPool;
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;
use uuid::Uuid;

#[sqlx::test]
async fn actual_http_events_keep_only_fixed_metadata_and_ignore_client_request_ids(pool: PgPool) {
    let (app, mail) = app(pool).await;
    let capture = Capture::default();
    let client_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let canary = "private-request-observation-canary";
    let mut ids = Vec::new();
    for (method, path, expected) in [
        (
            "GET",
            format!("/v1/session?token={canary}"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            format!("/v1/email/start?token={canary}"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("x-request-id", client_id)
            .header("authorization", format!("Bearer {canary}"))
            .header("cookie", format!("__Host-auth-session={canary}"))
            .header("origin", format!("https://{canary}.example"))
            .header("content-type", "application/json")
            .body(Body::from(format!(
                "{{\"email\":\"{canary}@example.test\"}}"
            )))
            .unwrap();
        let response = app
            .clone()
            .oneshot(request)
            .with_subscriber(capture.dispatcher())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let id = response.headers()["x-request-id"]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(Uuid::parse_str(&id).is_ok());
        assert_ne!(id, client_id);
        ids.push(id);
    }
    assert_ne!(ids[0], ids[1]);
    assert!(mail.sign_ins.lock().unwrap().is_empty());
    let events = capture.events();
    assert_eq!(events.len(), 2);
    for (index, event) in events.iter().enumerate() {
        let mut keys: Vec<_> = event.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "completion",
                "duration_micros",
                "message",
                "request_id",
                "status"
            ]
        );
        assert_eq!(event["request_id"], ids[index]);
        assert_eq!(event["completion"], "response");
        assert_eq!(event["message"], "http_request_completed");
        assert!(event["duration_micros"].as_u64().is_some());
        assert_eq!(event["status"], [401, 403][index]);
    }
    let rendered = serde_json::to_string(&events).unwrap();
    assert!(!rendered.contains(canary));
    assert!(!rendered.contains(client_id));
}
