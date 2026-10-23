use super::*;
use auth_core::{IssuerClientAuthentication, IssuerTokenError};

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn explicit_http_consent_delivers_one_bound_code_without_new_local_session(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let sessions = f.count("auth_sessions").await;
    let attempt = f.prepare().await;
    assert_eq!(f.count("auth_issuer_subjects").await, 0);
    assert_eq!(f.count("auth_sessions").await, sessions);
    let approved = f
        .send(
            "/v1/oidc/consent/approve",
            Fixture::decision(&attempt),
            &attempt.cookies,
        )
        .await;
    assert_eq!(approved.status(), 200);
    assert!(cookie(&approved, "__Host-auth-issuer-handle=").ends_with('='));
    assert!(cookie(&approved, "__Host-auth-issuer-browser=").ends_with('='));
    assert!(
        !approved
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("__Host-auth-session="))
    );
    let response = read(approved).await;
    let url = url::Url::parse(response["redirect_uri"].as_str().unwrap()).unwrap();
    assert_eq!(url.port(), Some(49152));
    assert!(
        url.query_pairs()
            .any(|(k, v)| k == "state" && v == "original-state")
    );
    assert!(url.query_pairs().any(|(k, v)| k == "iss" && v == ORIGIN));
    let code = Secret::parse(
        url.query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned(),
    )
    .unwrap();
    let auth = IssuerClientAuthentication::public(f.client.client()).unwrap();
    assert!(matches!(
        f.service
            .redeem(
                &auth,
                &code,
                "http://127.0.0.1:49153/callback",
                &f.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    let grant = f
        .service
        .redeem(
            &auth,
            &code,
            "http://127.0.0.1:49152/callback",
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(grant.nonce(), "original-nonce");
    assert_eq!(f.count("auth_sessions").await, sessions);
    assert_eq!(f.count("auth_users").await, 1);
    assert_eq!(f.count("auth_issuer_subjects").await, 1);
    let replay = f
        .send(
            "/v1/oidc/consent/approve",
            Fixture::decision(&attempt),
            &attempt.cookies,
        )
        .await;
    assert_eq!(replay.status(), 401);
    assert!(!replay.headers().contains_key(header::SET_COOKIE));
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn denial_only_returns_bound_error_and_logout_clears_pending_transport_proofs(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.prepare().await;
    let cancelled = f
        .send(
            "/v1/oidc/consent/cancel",
            Fixture::decision(&attempt),
            &attempt.cookies,
        )
        .await;
    assert_eq!(cancelled.status(), 200);
    let result = read(cancelled).await;
    let url = url::Url::parse(result["redirect_uri"].as_str().unwrap()).unwrap();
    assert!(
        url.query_pairs()
            .any(|(k, v)| k == "error" && v == "access_denied")
    );
    assert!(!url.query_pairs().any(|(k, _)| k == "code"));
    assert_eq!(f.count("auth_issuer_subjects").await, 0);
    assert_eq!(f.count("auth_issuer_authorizations").await, 0);
    let pending = f.prepare().await;
    let logged_out = f.send("/v1/logout", json!({}), &pending.cookies).await;
    assert_eq!(logged_out.status(), 204);
    for name in [
        "__Host-auth-session=",
        "__Host-auth-issuer-browser=",
        "__Host-auth-issuer-handle=",
        "__Host-auth-issuer-operation=",
    ] {
        assert!(cookie(&logged_out, name).ends_with('='));
    }
    let denied = f
        .send(
            "/v1/oidc/consent/approve",
            Fixture::decision(&pending),
            &pending.cookies,
        )
        .await;
    assert_eq!(denied.status(), 401);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn failed_http_audit_keeps_private_proofs_and_pending_state_for_a_valid_retry(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.prepare().await;
    sqlx::query("ALTER TABLE auth_audit ADD CONSTRAINT test_http_issuer_audit CHECK(kind<>'issuer_authorized')").execute(&f.pool).await.unwrap();
    let failed = f
        .send(
            "/v1/oidc/consent/approve",
            Fixture::decision(&attempt),
            &attempt.cookies,
        )
        .await;
    assert_eq!(failed.status(), 503);
    assert!(!failed.headers().contains_key(header::SET_COOKIE));
    assert_eq!(f.count("auth_issuer_subjects").await, 0);
    sqlx::query("ALTER TABLE auth_audit DROP CONSTRAINT test_http_issuer_audit")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.send(
            "/v1/oidc/consent/approve",
            Fixture::decision(&attempt),
            &attempt.cookies
        )
        .await
        .status(),
        200
    );
}
