use super::setup::*;
use auth_core::{OidcJitPolicy, Secret};
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test]
async fn binding_issuer_and_nonce_failures_never_grant_a_session(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    for (key, value) in [
        ("state", Secret::generate().unwrap().expose().to_owned()),
        ("issuer", "https://wrong.example".to_owned()),
    ] {
        let mut input = a.callback.clone();
        input[key] = json!(value);
        let r = f.post("finish", input, &a.cookie).await;
        assert_eq!(r.status(), 401);
        no_session(&r);
        cleared(&r);
        assert_eq!(f.facts().await, (0, 0, 0, 1));
    }
    for cookie in [
        "".to_owned(),
        format!(
            "{}; __Host-auth-oidc-signin-state={}",
            a.cookie, a.params["state"]
        ),
        a.cookie
            .replace("__Host-auth-oidc-signin-", "__Host-auth-oidc-delete-"),
    ] {
        let r = f.post("finish", a.callback.clone(), &cookie).await;
        assert_eq!(r.status(), 401);
        no_session(&r);
        cleared(&r);
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    f.prepare(
        &a,
        "owned",
        Some(("nonce", json!(Secret::generate().unwrap().expose()))),
    )
    .await;
    let r = f.post("finish", a.callback, &a.cookie).await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    cleared(&r);
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
}

#[sqlx::test]
async fn provider_infrastructure_failure_is_503_and_consumed_state_stays_consumed(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    f.provider.unavailable.store(true, Ordering::SeqCst);
    let r = f.post("finish", a.callback.clone(), &a.cookie).await;
    assert_eq!(r.status(), 503);
    no_session(&r);
    cleared(&r);
    assert_eq!(body(r).await, json!({"code":"temporarily_unavailable"}));
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    f.provider.unavailable.store(false, Ordering::SeqCst);
    assert_eq!(f.post("finish", a.callback, &a.cookie).await.status(), 401);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
}

#[sqlx::test]
async fn failed_final_audit_rolls_back_identity_and_session_but_not_consumption(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    sqlx::raw_sql("CREATE FUNCTION reject_oidc_http_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned audit fault'; END $$; CREATE TRIGGER reject_oidc_http_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION reject_oidc_http_audit();").execute(&f.pool).await.expect("test infrastructure: install final audit tripwire");
    let r = f.post("finish", a.callback.clone(), &a.cookie).await;
    assert_eq!(r.status(), 503);
    no_session(&r);
    cleared(&r);
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    assert_eq!(f.post("finish", a.callback, &a.cookie).await.status(), 401);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
}

#[sqlx::test]
async fn jit_denial_creates_no_contact_owner_or_session(pool: PgPool) {
    let f = Fixture::with_jit(pool, OidcJitPolicy::Deny).await;
    let a = f.start().await;
    let r = f.post("finish", a.callback, &a.cookie).await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    cleared(&r);
    assert_eq!(f.facts().await, (0, 0, 0, 0));
}

#[sqlx::test]
async fn concurrent_callback_posts_have_one_committed_session_and_one_exchange(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let (first, second) = tokio::join!(
        f.post("finish", a.callback.clone(), &a.cookie),
        f.post("finish", a.callback.clone(), &a.cookie)
    );
    let mut statuses = [first.status().as_u16(), second.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [204, 401]);
    let denied = if first.status() == 401 {
        &first
    } else {
        &second
    };
    no_session(denied);
    cleared(denied);
    assert_eq!(f.facts().await, (1, 1, 1, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
}

#[sqlx::test]
async fn expired_attempt_fails_before_exchange_and_cancel_still_clears_local_proof(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    sqlx::query("UPDATE auth_oauth_transactions SET created_at=statement_timestamp()-interval '6 minutes',expires_at=statement_timestamp()-interval '1 minute'")
        .execute(&f.pool).await.expect("test infrastructure: expire owned attempt");
    let expired_with_original_cap: bool = sqlx::query_scalar("SELECT expires_at<clock_timestamp() AND expires_at-created_at=interval '5 minutes' FROM auth_oauth_transactions")
        .fetch_one(&f.pool).await.expect("test infrastructure: observe exact expiry arrangement");
    assert!(
        expired_with_original_cap,
        "expiry fixture must preserve the five-minute cap"
    );
    let r = f.post("finish", a.callback, &a.cookie).await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    cleared(&r);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    let r = f.post("cancel", json!({}), &a.cookie).await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    cleared(&r);
    let (users, sessions, identities, _) = f.facts().await;
    assert_eq!((users, sessions, identities), (0, 0, 0));
}

#[sqlx::test]
async fn disabled_source_is_denied_before_token_post(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    f.store
        .disable_oauth_connection(
            f.policy.configuration().realm(),
            f.policy.configuration().connection(),
            f.policy.configuration().client(),
        )
        .await
        .unwrap();
    let r = f.post("finish", a.callback, &a.cookie).await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    cleared(&r);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.facts().await, (0, 0, 0, 0));
}

#[sqlx::test]
async fn administrative_revision_change_does_not_adopt_old_browser_proof(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let changed = f
        .store
        .configure_oidc_identity_policy(&f.policy)
        .await
        .unwrap();
    assert_ne!(
        changed.configuration().revision(),
        f.policy.configuration().revision()
    );
    let r = f.post("finish", a.callback, &a.cookie).await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    cleared(&r);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.facts().await, (0, 0, 0, 0));
}

#[sqlx::test]
async fn missing_issuer_wrong_audience_and_missing_nonce_fail_closed(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let mut missing = a.callback.clone();
    missing.as_object_mut().unwrap().remove("issuer");
    let r = f.post("finish", missing, &a.cookie).await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.post("cancel", json!({}), &a.cookie).await.status(), 204);
    for (key, value) in [("aud", json!("wrong-client")), ("nonce", json!(null))] {
        let a = f.start().await;
        f.prepare(&a, "owned", Some((key, value))).await;
        let r = f.post("finish", a.callback, &a.cookie).await;
        assert_eq!(r.status(), 401);
        no_session(&r);
        cleared(&r);
        assert_eq!(f.facts().await, (0, 0, 0, 0));
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 2);
    let a = f.start().await;
    assert_eq!(f.post("finish", a.callback, &a.cookie).await.status(), 204);
}

#[sqlx::test]
async fn discovery_infrastructure_failure_issues_no_cookies_and_cancels_pending(pool: PgPool) {
    let f = Fixture::new(pool).await;
    f.provider
        .documents_unavailable
        .store(true, Ordering::SeqCst);
    let r = f.post("start", json!({}), "").await;
    assert_eq!(r.status(), 503);
    assert_eq!(
        r.headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .count(),
        0
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    f.provider
        .documents_unavailable
        .store(false, Ordering::SeqCst);
    let a = f.start().await;
    assert_eq!(f.post("finish", a.callback, &a.cookie).await.status(), 204);
}

#[sqlx::test]
async fn all_four_cookie_components_reject_tampering_duplicates_and_missing_values(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    for part in a.cookie.split("; ") {
        let (name, _) = part.split_once('=').unwrap();
        for cookie in [
            a.cookie.replace(
                part,
                &format!("{name}={}", Secret::generate().unwrap().expose()),
            ),
            format!("{}; {part}", a.cookie),
            a.cookie
                .split("; ")
                .filter(|value| *value != part)
                .collect::<Vec<_>>()
                .join("; "),
        ] {
            let r = f.post("finish", a.callback.clone(), &cookie).await;
            assert_eq!(r.status(), 401);
            no_session(&r);
            cleared(&r);
        }
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(f.facts().await, (0, 0, 0, 1));
    assert_eq!(f.post("finish", a.callback, &a.cookie).await.status(), 204);
}
