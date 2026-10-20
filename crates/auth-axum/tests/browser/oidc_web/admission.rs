use super::setup::*;
use serde_json::json;
use sqlx::PgPool;
use std::{sync::atomic::Ordering, time::Duration};

#[sqlx::test]
async fn cold_discovery_contention_is_bounded_and_never_leaves_denied_attempt_authority(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    f.provider.hold_discovery.store(true, Ordering::SeqCst);
    let app = f.app.clone();
    let first = tokio::spawn(async move {
        use tower::ServiceExt;
        app.oneshot(crate::support::post(
            &format!("{ROOT}/start"),
            "{}",
            Some(""),
            Some(ORIGIN),
        ))
        .await
        .unwrap()
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        f.provider.discovery_entered.notified(),
    )
    .await
    .expect("test infrastructure: actual cold discovery request entered");
    let denied = tokio::time::timeout(Duration::from_secs(5), f.post("start", json!({}), ""))
        .await
        .expect("cache contention must reject without waiting behind provider I/O");
    assert_eq!(denied.status(), 429);
    no_session(&denied);
    assert_eq!(
        denied
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .count(),
        0
    );
    assert_eq!(body(denied).await, json!({"code":"rate_limited"}));
    assert!(!first.is_finished());
    assert_eq!(
        f.facts().await,
        (0, 0, 0, 1),
        "only the admitted start remains; denied start was cancelled"
    );
    f.provider.hold_discovery.store(false, Ordering::SeqCst);
    f.provider.discovery_release.notify_one();
    let admitted = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .expect("test infrastructure: released cold start completes")
        .unwrap();
    assert_eq!(admitted.status(), 200);
    no_session(&admitted);
    let cookie = cookies(&admitted);
    assert_eq!(f.post("cancel", json!({}), &cookie).await.status(), 204);
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
}
