use super::*;

#[sqlx::test(migrations = "./migrations")]
async fn code_confirmation_and_rotation_preserve_authority_and_keep_only_verifiers(pool: PgPool) {
    let f = Setup::new(pool.clone(), false).await;
    let before: (String, String, String) = sqlx::query_as("SELECT u.authentication_policy,s.authentication_method,s.authenticated_at::text FROM auth_users u JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id WHERE u.realm_id=$1 AND u.id=$2 AND s.token_hash=$3")
        .bind(f.f.realm).bind(f.owner).bind(f.f.session.verifier().as_slice()).fetch_one(&pool).await.unwrap();
    let first = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
    assert!(f.active().await.is_none());
    assert_eq!(f.counts().await, (1, 0, 0));
    f.flow
        .confirm(&f.f.session, SOURCE, first.id, &first.code)
        .await
        .unwrap();
    let active = f.active().await.unwrap();
    assert!(active.0 == first.id && active.1 == first.code.verifier());
    let snapshot = f.snapshot().await;
    assert!(matches!(
        f.flow
            .confirm(&f.f.session, SOURCE, first.id, &first.code)
            .await,
        Err(Error::Unauthorized)
    ));
    f.unchanged(snapshot).await;
    let second = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
    assert!(
        f.active().await.unwrap() == active,
        "preparation cannot invalidate the existing saved code"
    );
    let snapshot = f.snapshot().await;
    assert!(matches!(
        f.flow
            .confirm(&f.f.session, SOURCE, second.id, &first.code)
            .await,
        Err(Error::Unauthorized)
    ));
    f.unchanged(snapshot).await;
    f.flow
        .confirm(&f.f.session, SOURCE, second.id, &second.code)
        .await
        .unwrap();
    let rotated = f.active().await.unwrap();
    assert!(rotated.0 == second.id && rotated.1 == second.code.verifier() && rotated.1 != active.1);
    assert_eq!(f.counts().await, (0, 2, 2));
    let after: (String, String, String) = sqlx::query_as("SELECT u.authentication_policy,s.authentication_method,s.authenticated_at::text FROM auth_users u JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id WHERE u.realm_id=$1 AND u.id=$2 AND s.token_hash=$3")
        .bind(f.f.realm).bind(f.owner).bind(f.f.session.verifier().as_slice()).fetch_one(&pool).await.unwrap();
    assert!(
        before == after,
        "configuration cannot activate policy or refresh authentication"
    );
    let attribution: bool = sqlx::query_scalar("SELECT bool_and(schema_version=1 AND user_id=$2 AND actor_session_id=(SELECT id FROM auth_sessions WHERE realm_id=$1 AND token_hash=$3) AND session_id IS NULL AND passkey_id IS NULL) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovery_configured'")
        .bind(f.f.realm).bind(f.owner).bind(f.f.session.verifier().as_slice()).fetch_one(&pool).await.unwrap();
    assert!(attribution);
}

#[sqlx::test(migrations = "./migrations")]
async fn email_free_setup_has_no_fabricated_notice_and_no_weaker_fallback(pool: PgPool) {
    let f = Setup::new(pool, true).await;
    let code = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
    f.flow
        .confirm(&f.f.session, SOURCE, code.id, &code.code)
        .await
        .unwrap();
    assert_eq!(f.counts().await, (0, 1, 0));
    assert!(matches!(
        f.flow.prepare(&f.weak, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    let user =
        f.f.store
            .authenticate(f.f.realm, f.f.session.verifier())
            .await
            .unwrap();
    assert!(user.email.is_none());
    assert!(matches!(
        f.f.store.authenticate(f.f.realm, f.weak.verifier()).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn setup_is_bound_to_exact_session_pending_code_realm_and_rp(pool: PgPool) {
    let mut f = Setup::new(pool.clone(), false).await;
    let code = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
    let second_session = f.f.sign_in_with_key(&mut f.token).await;
    let snapshot = f.snapshot().await;
    for mode in ["session", "realm", "rp", "id", "code"] {
        let mut request = f.request();
        let mut id = code.id;
        let mut hash = code.code.verifier();
        match mode {
            "session" => request.session = second_session.verifier(),
            "realm" => request.realm = Uuid::new_v4(),
            "rp" => request.rp_id = "other.example.com".into(),
            "id" => id = Uuid::new_v4(),
            "code" => hash = Secret::generate().unwrap().verifier(),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                f.f.store
                    .confirm_passkey_recovery_code(&request, id, hash)
                    .await,
                Err(Error::Unauthorized)
            ),
            "{mode} must reject exactly"
        );
        f.unchanged(snapshot.clone()).await;
    }
    f.flow
        .confirm(&f.f.session, SOURCE, code.id, &code.code)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn weak_methods_and_expired_authority_cannot_prepare_or_confirm(pool: PgPool) {
    let f = Setup::new(pool.clone(), false).await;
    let code = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
    for scenario in [
        "email",
        "password",
        "legacy_unknown",
        "stale",
        "future",
        "idle",
        "absolute",
        "revoked",
    ] {
        // Restore actual assertion provenance/time policy, then perturb only the negative fixture.
        sqlx::query("UPDATE auth_sessions SET authentication_method=$3,authenticated_at=clock_timestamp(),last_seen_at=clock_timestamp(),expires_at=clock_timestamp()+interval '7 days',revoked_at=NULL WHERE realm_id=$1 AND token_hash=$2")
            .bind(f.f.realm).bind(f.f.session.verifier().as_slice()).bind(if ["email","password","legacy_unknown"].contains(&scenario) {scenario} else {"passkey"}).execute(&pool).await.unwrap();
        let sql = match scenario {
            "stale" => Some(
                "UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE realm_id=$1 AND token_hash=$2",
            ),
            "future" => Some(
                "UPDATE auth_sessions SET authenticated_at=clock_timestamp()+interval '1 minute' WHERE realm_id=$1 AND token_hash=$2",
            ),
            "idle" => Some(
                "UPDATE auth_sessions SET last_seen_at=clock_timestamp()-interval '31 minutes' WHERE realm_id=$1 AND token_hash=$2",
            ),
            "absolute" => Some(
                "UPDATE auth_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE realm_id=$1 AND token_hash=$2",
            ),
            "revoked" => Some(
                "UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND token_hash=$2",
            ),
            _ => None,
        };
        if let Some(sql) = sql {
            sqlx::query(sql)
                .bind(f.f.realm)
                .bind(f.f.session.verifier().as_slice())
                .execute(&pool)
                .await
                .unwrap();
        }
        // Isolate authorization from the independently covered durable admission budget.
        sqlx::query("DELETE FROM auth_rate_buckets WHERE realm_id=$1")
            .bind(f.f.realm)
            .execute(&pool)
            .await
            .unwrap();
        let snapshot = f.snapshot().await;
        assert!(
            matches!(
                f.flow.prepare(&f.f.session, SOURCE).await,
                Err(Error::Unauthorized)
            ),
            "{scenario} preparation"
        );
        assert!(
            matches!(
                f.flow
                    .confirm(&f.f.session, SOURCE, code.id, &code.code)
                    .await,
                Err(Error::Unauthorized)
            ),
            "{scenario} confirmation"
        );
        f.unchanged(snapshot).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_confirmations_spend_durable_sensitive_action_admission(pool: PgPool) {
    let f = Setup::new(pool, false).await;
    let code = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
    let wrong = Secret::generate().unwrap();
    for _ in 0..9 {
        assert!(matches!(
            f.flow.confirm(&f.f.session, SOURCE, code.id, &wrong).await,
            Err(Error::Unauthorized)
        ));
    }
    assert!(matches!(
        f.flow
            .confirm(&f.f.session, SOURCE, code.id, &code.code)
            .await,
        Err(Error::RateLimited)
    ));
    assert!(f.active().await.is_none());
    assert_eq!(f.counts().await, (1, 0, 0));
}
