use super::setup::*;
use std::{sync::atomic::Ordering, time::Duration};

#[sqlx::test]
async fn http_link_disable_during_provider_post_commits_no_identity_or_cookie(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (owner, session) = f.owner("owner@owned.example").await;
    let a = f.start("apple", owner, &session).await;
    let raw = f.issue("apple", &a, "disable").await;
    f.apple.hold.store(true, Ordering::SeqCst);
    let finish = f.finish("apple", &a, &raw);
    let disable = async {
        tokio::time::timeout(Duration::from_secs(5), f.apple.entered.notified())
            .await
            .expect("actual Apple token POST entered");
        let c = f.apple_policy.configuration();
        f.store
            .disable_oauth_connection(c.realm(), c.connection(), c.client())
            .await
            .unwrap();
        f.apple.release.notify_one();
    };
    let (r, ()) = tokio::join!(finish, disable);
    assert_eq!(r.status(), 401);
    no_session(&r);
    assert!(
        f.inventory(&session).await["providers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(f.apple.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.get("/v1/session", &session).await.status(), 200);
}

#[sqlx::test]
async fn http_link_audit_failure_rolls_back_identity_and_notice_without_replaying_code(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (owner, session) = f.owner("owner@owned.example").await;
    let a = f.start("google", owner, &session).await;
    let raw = f.issue("google", &a, "atomic").await;
    sqlx::raw_sql("CREATE FUNCTION reject_social_http_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind = 'oidc_identity_linked' THEN RAISE EXCEPTION 'owned social audit fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_social_http_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION reject_social_http_audit();").execute(&f.pool).await.unwrap();
    let r = f.finish("google", &a, &raw).await;
    assert_eq!(r.status(), 503);
    no_session(&r);
    assert!(
        f.inventory(&session).await["providers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let notices: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_security_notifications WHERE realm_id=$1 AND kind='providers_changed'",
    )
    .bind(f.auth.realm())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(notices, 0);
    sqlx::query("DROP TRIGGER reject_social_http_audit ON auth_audit")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(f.finish("google", &a, &raw).await.status(), 401);
    assert_eq!(f.google.posts.load(Ordering::SeqCst), 1);
    let next = f.start("google", owner, &session).await;
    let raw = f.issue("google", &next, "valid-after-fault").await;
    assert_eq!(f.finish("google", &next, &raw).await.status(), 204);
}
