use super::setup::*;
use auth_core::Secret;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test]
async fn google_http_unavailable_preparation_and_token_io_are_not_signed_authentication_failures(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    f.provider
        .documents_unavailable
        .store(true, Ordering::SeqCst);
    let r = f.post(ROOT, "start", json!({}), "").await;
    assert_eq!(r.status(), 503);
    no_session(&r);
    assert!(r.headers().get_all("set-cookie").iter().next().is_none());
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert!(f.provider.document_gets.load(Ordering::SeqCst) > 0);
    f.provider
        .documents_unavailable
        .store(false, Ordering::SeqCst);
    let a = f.start(ROOT, "").await;
    let query = f
        .issue(
            &a,
            json!({"nonce":Secret::generate().unwrap().expose(),"auth_time":f.now().await}),
        )
        .await;
    assert_eq!(
        f.post(ROOT, "finish", json!({"query":query}), &a.cookie)
            .await
            .status(),
        401
    );
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    let a = f.start(ROOT, "").await;
    let query = f.fresh(&a).await;
    f.provider.unavailable.store(true, Ordering::SeqCst);
    let r = f
        .post(ROOT, "finish", json!({"query":query}), &a.cookie)
        .await;
    assert_eq!(r.status(), 503);
    no_session(&r);
    f.provider.unavailable.store(false, Ordering::SeqCst);
    assert_eq!(
        f.post(ROOT, "finish", json!({"query":query}), &a.cookie)
            .await
            .status(),
        401
    );
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.signin().await;
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}

#[sqlx::test]
async fn google_http_final_audit_failure_rolls_back_and_never_emits_a_session_cookie(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start(ROOT, "").await;
    let query = f.fresh(&a).await;
    sqlx::raw_sql("CREATE FUNCTION owned_google_http_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned Google HTTP audit fault'; END $$; CREATE TRIGGER owned_google_http_audit_fault BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION owned_google_http_audit_fault()")
        .execute(&f.pool).await.expect("test infrastructure: install actual Google HTTP audit fault");
    let r = f
        .post(ROOT, "finish", json!({"query":query}), &a.cookie)
        .await;
    assert_eq!(r.status(), 503);
    no_session(&r);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    sqlx::raw_sql("DROP TRIGGER owned_google_http_audit_fault ON auth_audit")
        .execute(&f.pool)
        .await
        .expect("test infrastructure: remove actual Google HTTP audit fault");
    assert_eq!(
        f.post(ROOT, "finish", json!({"query":query}), &a.cookie)
            .await
            .status(),
        401
    );
    let current = f.signin().await;
    let a = f.start(DELETE, &current).await;
    let query = f.fresh(&a).await;
    sqlx::raw_sql("CREATE TRIGGER owned_google_http_audit_fault BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION owned_google_http_audit_fault()")
        .execute(&f.pool).await.expect("test infrastructure: install deletion audit fault");
    let r = f
        .post(
            DELETE,
            "finish",
            json!({"confirmation":"delete my account","query":query}),
            &format!("{}; {current}", a.cookie),
        )
        .await;
    assert_eq!(r.status(), 503);
    no_session(&r);
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
    sqlx::raw_sql("DROP TRIGGER owned_google_http_audit_fault ON auth_audit; DROP FUNCTION owned_google_http_audit_fault()")
        .execute(&f.pool).await.expect("test infrastructure: remove deletion audit fault");
    let a = f.start(DELETE, &current).await;
    let query = f.fresh(&a).await;
    assert_eq!(
        f.post(
            DELETE,
            "finish",
            json!({"confirmation":"delete my account","query":query}),
            &format!("{}; {current}", a.cookie)
        )
        .await
        .status(),
        204
    );
}
