use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn http_recovery_only_sets_session_after_actual_candidate_assertion_and_atomic_completion(
    pool: PgPool,
) {
    for email_free in [false, true] {
        let r = Recovery::new(pool.clone(), email_free).await;
        let claim = r.start().await;
        assert_eq!(claim["ready"], false);
        assert_eq!(claim["notification_required"], !email_free);
        rejected(
            send(&r.app, REPLACE, r.target(&claim), Some(&r.cookie)).await,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
        r.mature(&claim).await;
        // All-keys-lost flow uses no prior session authority.
        sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND revoked_at IS NULL").bind(r.f.auth.realm()).execute(&pool).await.unwrap();
        let old_keys: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT credential_id FROM auth_passkeys WHERE realm_id=$1")
                .bind(r.f.auth.realm())
                .fetch_all(&pool)
                .await
                .unwrap();
        let (id, signed, mut token) = r.assertion(&claim).await;
        let current: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT credential_id FROM auth_passkeys WHERE realm_id=$1")
                .bind(r.f.auth.realm())
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(old_keys, current, "registration stays private");
        let response = send(
            &r.app,
            FINISH,
            r.finish_body(&claim, id, &signed),
            Some(&r.cookie),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let cookies: Vec<&str> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|c| c.to_str().unwrap())
            .collect();
        let sessions: Vec<_> = cookies
            .iter()
            .filter(|c| c.starts_with("__Host-auth-session="))
            .collect();
        assert_eq!(sessions.len(), 1);
        let cookie = sessions[0].split(';').next().unwrap().to_owned();
        for name in [
            "__Host-auth-browser",
            "__Host-auth-reset",
            "__Host-auth-email-change",
            "__Host-auth-delete",
            "__Host-auth-passkey",
            "__Host-auth-attach",
        ] {
            assert!(
                cookies
                    .iter()
                    .any(|c| c.starts_with(&format!("{name}=;")) && c.contains("Max-Age=0"))
            );
        }
        assert!(
            !cookies.iter().any(|c| c.starts_with(RECOVERY_COOKIE)),
            "independent capability retained for any other owned claim"
        );
        let session_response = r
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/session")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session_response.status(), StatusCode::OK);
        assert_eq!(json(session_response).await["id"], r.f.owner.to_string());
        let before = r.snapshot().await;
        rejected(
            send(
                &r.app,
                FINISH,
                r.finish_body(&claim, id, &signed),
                Some(&r.cookie),
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
        assert!(r.snapshot().await == before);
        // Lost finish response resolves through normal actual key sign-in.
        let login =
            r.f.sign_in
                .begin_account(r.f.owner, &r.f.browser, "recovery-finish-retry")
                .await
                .unwrap();
        let assertion = token
            .perform_auth(ORIGIN.parse().unwrap(), login.options.public_key, 120_000)
            .unwrap();
        assert!(
            r.f.sign_in
                .finish(
                    &r.f.browser,
                    "recovery-finish-retry",
                    login.transaction,
                    &assertion
                )
                .await
                .is_ok()
        );
        let facts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovered' AND session_id IS NOT NULL AND actor_session_id IS NULL),(SELECT count(*) FROM auth_security_notifications WHERE realm_id=$1 AND kind='passkey_recovery_completed')").bind(r.f.auth.realm()).fetch_one(&pool).await.unwrap();
        assert_eq!(facts, (1, i64::from(!email_free)));
    }
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn concurrent_http_completion_has_one_session_cookie_and_one_terminal_fact(pool: PgPool) {
    let r = Recovery::new(pool.clone(), true).await;
    let claim = r.start().await;
    r.mature(&claim).await;
    let (id, signed, _) = r.assertion(&claim).await;
    let body = r.finish_body(&claim, id, &signed);
    let (first, second) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            send(&r.app, FINISH, body.clone(), Some(&r.cookie)),
            send(&r.app, FINISH, body, Some(&r.cookie))
        )
    })
    .await
    .expect("test infrastructure: competing HTTP completion must terminate");
    let (winner, loser) = if first.status() == StatusCode::NO_CONTENT {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(winner.status(), StatusCode::NO_CONTENT);
    assert!(winner.headers().get(header::SET_COOKIE).is_some());
    rejected(loser, StatusCode::UNAUTHORIZED, "authentication_required").await;
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_sessions WHERE realm_id=$1 AND revoked_at IS NULL),(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovered')").bind(r.f.auth.realm()).fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (1, 1));
}
