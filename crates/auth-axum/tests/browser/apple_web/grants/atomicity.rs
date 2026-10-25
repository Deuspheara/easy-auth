use super::*;
use std::time::Duration;

#[sqlx::test]
async fn captured_http_audit_failure_rolls_back_authority_and_envelope(pool: PgPool) {
    let f = captured(pool).await;
    sqlx::raw_sql("CREATE FUNCTION reject_capture_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned capture audit fault'; END $$; CREATE TRIGGER reject_capture_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION reject_capture_audit();").execute(&f.pool).await.unwrap();
    let a = f.start().await;
    let raw = f.issue(&a, json!({}), None).await;
    let response = f.post("finish", json!({"response":raw}), &a.cookie).await;
    assert_eq!(response.status(), 503);
    no_session(&response);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(grants(&f).await, 0);
    sqlx::query("DROP TRIGGER reject_capture_audit ON auth_audit")
        .execute(&f.pool)
        .await
        .unwrap();
    f.signin().await;
    assert_eq!(grants(&f).await, 1);
}

#[sqlx::test]
async fn captured_http_source_disable_during_actual_token_post_rejects_late_result(pool: PgPool) {
    let f = captured(pool).await;
    let a = f.start().await;
    let raw = f.issue(&a, json!({}), None).await;
    f.provider.hold.store(true, Ordering::SeqCst);
    let action = f.post("finish", json!({"response":raw}), &a.cookie);
    let disable = async {
        tokio::time::timeout(Duration::from_secs(5), f.provider.entered.notified())
            .await
            .unwrap();
        let c = f.policy.configuration();
        f.store
            .disable_oauth_connection(c.realm(), c.connection(), c.client())
            .await
            .unwrap();
        f.provider.release.notify_one();
    };
    let (response, ()) = tokio::join!(action, disable);
    assert_eq!(response.status(), 401);
    no_session(&response);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(grants(&f).await, 0);
}
