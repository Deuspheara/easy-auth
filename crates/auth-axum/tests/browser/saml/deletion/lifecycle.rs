use super::super::setup::ORIGIN;
use super::setup::Fixture;
use crate::support::post;
use axum::http::header;
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn cross_site_delivery_and_operation_selection_grant_nothing_before_explicit_real_commit(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let attempt = f.start("ordinary-subject").await;
    assert_eq!(f.base.facts().await, (1, 1, 1, 2, 1));
    let delivery = f
        .base
        .deliver("/saml/acs", &attempt, None, Some("https://idp.example"))
        .await;
    assert_eq!(delivery.status(), 200);
    assert!(delivery.headers().get(header::SET_COOKIE).is_none());
    let selected = f.select(&attempt, Some(&attempt.cookie)).await;
    assert_eq!(selected.status(), 200);
    assert!(selected.headers().get(header::SET_COOKIE).is_none());
    let value: serde_json::Value =
        serde_json::from_slice(&selected.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(value, serde_json::json!({"operation":"delete_account"}));
    assert_eq!(f.base.facts().await, (1, 1, 1, 2, 1));
    assert_eq!(
        f.finish(&attempt, "wrong", Some(&attempt.cookie))
            .await
            .status(),
        400
    );
    assert_eq!(f.base.facts().await, (1, 1, 1, 2, 1));
    assert_eq!(f.session().await.status(), 200);
    let result = f
        .finish(&attempt, "delete my account", Some(&attempt.cookie))
        .await;
    assert_eq!(result.status(), 204);
    assert!(
        result
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("__Host-auth-session=;"))
    );
    for name in [
        "__Host-auth-saml-delete-request=;",
        "__Host-auth-saml-delete-relay=;",
        "__Host-auth-saml-delete-browser=;",
    ] {
        assert!(
            result
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|v| v.to_str().unwrap().starts_with(name))
        );
    }
    assert_eq!(f.base.facts().await, (0, 0, 0, 4, 0));
    assert_eq!(f.session().await.status(), 401);
    assert_eq!(
        f.finish(&attempt, "delete my account", Some(&attempt.cookie))
            .await
            .status(),
        401
    );
    assert_eq!(f.base.facts().await, (0, 0, 0, 4, 0));
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn explicit_cancellation_preserves_account_session_and_replay_and_clears_only_deletion_proof(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let attempt = f.start("ordinary-subject").await;
    let cancelled = f
        .base
        .app
        .clone()
        .oneshot(post(
            "/v1/saml/account-delete/cancel",
            "{}",
            Some(&attempt.cookie),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(cancelled.status(), 204);
    assert_eq!(
        cancelled
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        3
    );
    assert_eq!(f.base.facts().await, (1, 1, 1, 2, 0));
    assert_eq!(f.session().await.status(), 200);
    assert_eq!(
        f.finish(&attempt, "delete my account", Some(&attempt.cookie))
            .await
            .status(),
        401
    );
    assert_eq!(f.base.facts().await, (1, 1, 1, 2, 0));
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn actual_signed_different_subject_and_storage_failure_cannot_erase_or_clear_current_session(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let other = f.start("other-subject").await;
    let rejected = f
        .finish(&other, "delete my account", Some(&other.cookie))
        .await;
    assert_eq!(rejected.status(), 401);
    assert!(
        !rejected
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("__Host-auth-session="))
    );
    assert_eq!(f.base.facts().await, (1, 1, 1, 2, 0));
    let valid = f.start("ordinary-subject").await;
    sqlx::raw_sql("CREATE FUNCTION reject_http_saml_erasure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned fixture storage failure'; END $$; CREATE TRIGGER reject_http_saml_erasure BEFORE INSERT ON auth_audit FOR EACH ROW WHEN (NEW.kind='account_deleted') EXECUTE FUNCTION reject_http_saml_erasure();").execute(&f.base.pool).await.unwrap();
    let unavailable = f
        .finish(&valid, "delete my account", Some(&valid.cookie))
        .await;
    assert_eq!(unavailable.status(), 503);
    assert!(
        !unavailable
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("__Host-auth-session="))
    );
    assert_eq!(f.base.facts().await, (1, 1, 1, 2, 0));
    assert_eq!(f.session().await.status(), 200);
    sqlx::raw_sql("DROP TRIGGER reject_http_saml_erasure ON auth_audit; DROP FUNCTION reject_http_saml_erasure();").execute(&f.base.pool).await.unwrap();
    let fresh = f.start("ordinary-subject").await;
    assert_eq!(
        f.finish(&fresh, "delete my account", Some(&fresh.cookie))
            .await
            .status(),
        204
    );
}
