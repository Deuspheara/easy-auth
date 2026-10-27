use super::*;

#[sqlx::test]
async fn captured_link_and_signin_unlink_locally_then_revoke_without_changing_retained_session(
    pool: PgPool,
) {
    let vault = vault();
    let f = captured(pool, vault.clone()).await;
    let (owner, current) = f.owner("owner@owned.example").await;
    let a = f.start("apple", owner, &current).await;
    let raw = f.issue("apple", &a, "captured-identity").await;
    let r = f.finish("apple", &a, &raw).await;
    assert_eq!(r.status(), 204);
    no_session(&r);
    assert_eq!(grants(&f).await, vec![("active".into(), 0, false)]);
    let response = f.post("/v1/apple/sign-in/start", json!({}), "").await;
    let cookie = super::super::setup::cookies(&response);
    let a = super::super::setup::Attempt {
        cookie,
        url: url::Url::parse(body(response).await["authorization_url"].as_str().unwrap()).unwrap(),
    };
    let raw = f.issue("apple", &a, "captured-identity").await;
    let response = f
        .post(
            "/v1/apple/sign-in/finish",
            json!({"response":raw}),
            &a.cookie,
        )
        .await;
    assert_eq!(response.status(), 204);
    let provider_session = crate::support::cookie(&response, "__Host-auth-session=");
    assert_eq!(
        body(f.get("/v1/session", &provider_session).await).await["id"],
        owner.to_string()
    );
    assert_eq!(grants(&f).await, vec![("active".into(), 0, false); 2]);
    assert_eq!(unlink(&f, owner, &provider_session).await.status(), 401);
    let http = worker::Http::new(&f);
    let worker = worker::create(&f, vault, http.clone());
    assert_eq!(
        worker.run_once().await.unwrap(),
        AppleRevocationOutcome::Idle
    );
    let response = unlink(&f, owner, &current).await;
    assert_eq!(response.status(), 204);
    no_session(&response);
    assert_eq!(
        http.calls.load(Ordering::SeqCst),
        0,
        "local unlink does not wait on provider"
    );
    assert_eq!(grants(&f).await, vec![("pending".into(), 0, false); 2]);
    assert_eq!(f.get("/v1/session", &provider_session).await.status(), 401);
    for _ in 0..2 {
        assert_eq!(
            worker.run_once().await.unwrap(),
            AppleRevocationOutcome::Confirmed
        );
    }
    assert_eq!(grants(&f).await, vec![("completed".into(), 1, true); 2]);
    assert_eq!(http.calls.load(Ordering::SeqCst), 2);
    assert_eq!(f.get("/v1/session", &current).await.status(), 200);
    assert_eq!(
        f.inventory(&current).await["providers"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[sqlx::test]
async fn provider_failure_keeps_job_pending_and_local_session_usable_without_busy_retry(
    pool: PgPool,
) {
    let vault = vault();
    let f = captured(pool, vault.clone()).await;
    let (owner, current) = f.owner("owner@owned.example").await;
    let a = f.start("apple", owner, &current).await;
    let raw = f.issue("apple", &a, "offline").await;
    assert_eq!(f.finish("apple", &a, &raw).await.status(), 204);
    assert_eq!(unlink(&f, owner, &current).await.status(), 204);
    let http = worker::Http::new(&f);
    http.failure.store(true, Ordering::SeqCst);
    let worker = worker::create(&f, vault, http.clone());
    assert_eq!(
        worker.run_once().await.unwrap(),
        AppleRevocationOutcome::Deferred(AppleRevocationFailure::Configuration)
    );
    assert_eq!(grants(&f).await, vec![("pending".into(), 1, false)]);
    assert_eq!(
        worker.run_once().await.unwrap(),
        AppleRevocationOutcome::Idle
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.get("/v1/session", &current).await.status(), 200);
}
