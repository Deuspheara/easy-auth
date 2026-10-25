use super::*;

#[sqlx::test]
async fn default_link_discards_credentials_with_capture_compiled(pool: PgPool) {
    let ordinary = Fixture::new(pool).await;
    let (owner, current) = ordinary.owner("ordinary@owned.example").await;
    let a = ordinary.start("apple", owner, &current).await;
    let raw = ordinary.issue("apple", &a, "discard").await;
    assert_eq!(ordinary.finish("apple", &a, &raw).await.status(), 204);
    assert!(grants(&ordinary).await.is_empty());
}

#[sqlx::test]
async fn explicit_link_requires_protection_without_fallback(pool: PgPool) {
    let f = super::super::composition::with_grants(pool, None).await;
    let (owner, current) = f.owner("captured@owned.example").await;
    let a = f.start("apple", owner, &current).await;
    let raw = f.issue("apple", &a, "no-vault").await;
    let r = f.finish("apple", &a, &raw).await;
    assert_eq!(r.status(), 503);
    no_session(&r);
    assert!(grants(&f).await.is_empty());
    assert!(
        f.inventory(&current).await["providers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(f.get("/v1/session", &current).await.status(), 200);
    assert_eq!(f.finish("apple", &a, &raw).await.status(), 401);
    assert_eq!(f.apple.posts.load(Ordering::SeqCst), 1);
}

#[sqlx::test]
async fn selected_link_audit_failure_rolls_back_grant_identity_and_notice(pool: PgPool) {
    let f = captured(pool, vault()).await;
    let (owner, current) = f.owner("owner@owned.example").await;
    let a = f.start("apple", owner, &current).await;
    let raw = f.issue("apple", &a, "atomic").await;
    sqlx::raw_sql("CREATE FUNCTION reject_capture_link_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='oidc_identity_linked' THEN RAISE EXCEPTION 'owned captured link audit fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_capture_link_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION reject_capture_link_audit();").execute(&f.pool).await.unwrap();
    let r = f.finish("apple", &a, &raw).await;
    assert_eq!(r.status(), 503);
    no_session(&r);
    assert!(grants(&f).await.is_empty());
    assert!(
        f.inventory(&current).await["providers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let notices:i64=sqlx::query_scalar("SELECT count(*) FROM auth_security_notifications WHERE realm_id=$1 AND kind='providers_changed'")
        .bind(f.auth.realm()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(notices, 0);
    sqlx::query("DROP TRIGGER reject_capture_link_audit ON auth_audit")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(f.finish("apple", &a, &raw).await.status(), 401);
    let a = f.start("apple", owner, &current).await;
    let raw = f.issue("apple", &a, "after-fault").await;
    assert_eq!(f.finish("apple", &a, &raw).await.status(), 204);
    assert_eq!(grants(&f).await.len(), 1);
}
