use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn browser_and_reserved_code_cancellation_never_authenticate_or_reopen_the_code(
    pool: PgPool,
) {
    for path in [CANCEL, CANCEL_CODE] {
        let r = Recovery::new(pool.clone(), true).await;
        let claim = r.start().await;
        let body = if path == CANCEL {
            r.target(&claim)
        } else {
            json!({"account_id":r.f.owner,"code":r.code.expose()})
        };
        let response = send(
            &r.app,
            path,
            body,
            if path == CANCEL {
                Some(&r.cookie)
            } else {
                None
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let before = r.snapshot().await;
        rejected(
            send(
                &r.app,
                RESUME,
                json!({"account_id":r.f.owner}),
                Some(&r.cookie),
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
        rejected(
            send(
                &r.app,
                START,
                json!({"account_id":r.f.owner,"code":r.code.expose()}),
                Some(&r.cookie),
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
        assert!(r.snapshot().await == before);
        let facts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovery_cancelled' AND actor_session_id IS NULL AND session_id IS NULL),(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovered')").bind(r.f.auth.realm()).fetch_one(&pool).await.unwrap();
        assert_eq!(facts, (1, 0));
    }
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn key_cancellation_requires_genuine_fresh_owned_session_and_ignores_no_client_owner_selector(
    pool: PgPool,
) {
    let r = Recovery::new(pool.clone(), true).await;
    let peer = Recovery::new(pool.clone(), true).await;
    let claim = r.start().await;
    for cookie in [
        None,
        Some(r.f.mailbox_cookie.clone()),
        Some(peer.f.cookie()),
    ] {
        rejected(
            send(&r.app, CANCEL_KEY, json!({}), cookie.as_deref()).await,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    rejected(
        send(&r.app, CANCEL_KEY, r.target(&claim), Some(&r.f.cookie())).await,
        StatusCode::BAD_REQUEST,
        "invalid_body",
    )
    .await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE realm_id=$1").bind(r.f.auth.realm()).execute(&pool).await.unwrap();
    rejected(
        send(&r.app, CANCEL_KEY, json!({}), Some(&r.f.cookie())).await,
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    let response = send(
        &r.app,
        CANCEL_CODE,
        json!({"account_id":r.f.owner,"code":r.code.expose()}),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
