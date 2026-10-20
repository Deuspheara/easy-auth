use super::setup::*;
use auth_core::*;
use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test]
async fn wrong_subject_and_missing_old_future_time_never_delete(pool: PgPool) {
    let f = Fixture::new(pool).await;
    for (subject, age) in [
        ("other", Some(0)),
        ("owned", None),
        ("owned", Some(301)),
        ("owned", Some(-60)),
    ] {
        let attempt = f.start().await;
        f.prepare_claims(&attempt, subject, age).await;
        let response = f.post("finish", attempt.callback, &attempt.cookie).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(cleared(&response), 4);
        assert!(f.exists().await);
        assert_eq!(f.pending().await, 0);
    }
    // Positive control uses the same source, policy and still-active session.
    let attempt = f.start().await;
    assert_eq!(
        f.post("finish", attempt.callback, &attempt.cookie)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
}

#[sqlx::test]
async fn tampered_or_duplicate_proof_never_reaches_provider(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    for part in attempt.cookie.split("; ").skip(1) {
        let (name, _) = part.split_once('=').unwrap();
        for altered in [
            attempt.cookie.replace(
                part,
                &format!("{name}={}", Secret::generate().unwrap().expose()),
            ),
            format!("{}; {part}", attempt.cookie),
            attempt
                .cookie
                .split("; ")
                .filter(|p| *p != part)
                .collect::<Vec<_>>()
                .join("; "),
        ] {
            let response = f.post("finish", attempt.callback.clone(), &altered).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(f.exists().await);
        }
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.pending().await, 1);
    assert_eq!(
        f.post("finish", attempt.callback, &attempt.cookie)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
}

#[sqlx::test]
async fn wrong_issuer_or_state_preserves_pending_and_has_fixed_error(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    for (key, value) in [
        ("state", json!(Secret::generate().unwrap().expose())),
        ("issuer", json!("https://other.example")),
        ("issuer", json!(null)),
    ] {
        let mut input = attempt.callback.clone();
        input[key] = value;
        let response = f.post("finish", input, &attempt.cookie).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body(response).await,
            json!({"code":"authentication_required"})
        );
    }
    assert_eq!(f.pending().await, 1);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.post("finish", attempt.callback, &attempt.cookie)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
}

#[sqlx::test]
async fn unavailable_token_transport_is_503_and_does_not_delete(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    f.provider.unavailable.store(true, Ordering::SeqCst);
    let response = f
        .post("finish", attempt.callback.clone(), &attempt.cookie)
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(cleared(&response), 4);
    assert_eq!(
        body(response).await,
        json!({"code":"temporarily_unavailable"})
    );
    assert!(f.exists().await);
    assert_eq!(f.pending().await, 0);
    f.provider.unavailable.store(false, Ordering::SeqCst);
    assert_eq!(
        f.post("finish", attempt.callback, &attempt.cookie)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test]
async fn storage_failure_is_503_and_rolls_back_account_deletion(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    sqlx::raw_sql("CREATE FUNCTION fail_deletion_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned test storage failure'; END $$; CREATE TRIGGER fail_deletion_audit BEFORE INSERT ON auth_audit FOR EACH ROW WHEN (NEW.kind='account_deleted') EXECUTE FUNCTION fail_deletion_audit();").execute(&f.pool).await.unwrap();
    let response = f.post("finish", attempt.callback, &attempt.cookie).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(cleared(&response), 4);
    assert_eq!(
        body(response).await,
        json!({"code":"temporarily_unavailable"})
    );
    assert!(f.exists().await);
    assert_eq!(f.pending().await, 0);
    assert!(f.auth.authenticate(&f.session).await.is_ok());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_oidc_deleted_subjects")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::raw_sql(
        "DROP TRIGGER fail_deletion_audit ON auth_audit; DROP FUNCTION fail_deletion_audit();",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    let next = f.start().await;
    assert_eq!(
        f.post("finish", next.callback, &next.cookie).await.status(),
        StatusCode::NO_CONTENT
    );
}

#[sqlx::test]
async fn failed_start_discovery_cancels_pending_without_issuing_proof(pool: PgPool) {
    let f = Fixture::new(pool).await;
    f.provider
        .documents_unavailable
        .store(true, Ordering::SeqCst);
    let response = f
        .post(
            "start",
            json!({"confirmation":"delete my account"}),
            &f.session_cookie(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .is_none()
    );
    assert_eq!(
        body(response).await,
        json!({"code":"temporarily_unavailable"})
    );
    assert_eq!(f.pending().await, 0);
    assert!(f.exists().await);
    assert!(f.auth.authenticate(&f.session).await.is_ok());
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
}
