use super::setup::*;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test]
async fn apple_http_disable_during_actual_token_post_cannot_set_session(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let raw = f.issue(&a, json!({}), None).await;
    f.provider.hold.store(true, Ordering::SeqCst);
    let action = f.post("finish", json!({"response":raw}), &a.cookie);
    let disabled = async {
        tokio::time::timeout(Duration::from_secs(5), f.provider.entered.notified())
            .await
            .expect("actual owned token POST entered");
        let c = f.policy.configuration();
        f.store
            .disable_oauth_connection(c.realm(), c.connection(), c.client())
            .await
            .unwrap();
        f.provider.release.notify_one();
    };
    let (r, ()) = tokio::join!(action, disabled);
    assert_eq!(r.status(), 401);
    no_session(&r);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
}

#[sqlx::test]
async fn apple_http_failed_audit_rolls_back_all_authority_and_keeps_state_consumed(pool: PgPool) {
    let f = Fixture::new(pool).await;
    sqlx::raw_sql("CREATE FUNCTION reject_apple_web_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned Apple HTTP audit fault'; END $$; CREATE TRIGGER reject_apple_web_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION reject_apple_web_audit();").execute(&f.pool).await.unwrap();
    let a = f.start().await;
    let raw = f.issue(&a, json!({}), None).await;
    let r = f.post("finish", json!({"response":raw}), &a.cookie).await;
    assert_eq!(r.status(), 503);
    no_session(&r);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    let replay = f.post("finish", json!({"response":raw}), &a.cookie).await;
    assert_eq!(replay.status(), 401);
    no_session(&replay);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    sqlx::query("DROP TRIGGER reject_apple_web_audit ON auth_audit")
        .execute(&f.pool)
        .await
        .unwrap();
    f.signin().await;
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}
