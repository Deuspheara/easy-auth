use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn http_code_confirmation_rotates_without_session_or_policy_upgrade_and_queues_retryable_notice(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone(), false).await;
    let mail = Arc::new(Mail::default());
    let auth = Auth::new(f.auth.realm(), f.store.clone(), mail.clone());
    let app = app(&f, auth.clone());
    let (id, code) = prepare(&app, &f).await;
    let before: (String,String,String) = sqlx::query_as("SELECT u.authentication_policy,s.authentication_method,s.authenticated_at::text FROM auth_users u JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id WHERE u.realm_id=$1 AND u.id=$2 AND s.token_hash=$3")
        .bind(f.auth.realm()).bind(f.owner).bind(f.session.verifier().as_slice()).fetch_one(&pool).await.unwrap();
    let input = json!({"id":id,"code":code.expose()});
    let response = send(&app, &f, CONFIRM, &input).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    let active: Vec<u8> = sqlx::query_scalar(
        "SELECT code_hash FROM auth_passkey_recovery_codes WHERE realm_id=$1 AND user_id=$2",
    )
    .bind(f.auth.realm())
    .bind(f.owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(active == code.verifier());
    rejected(
        send(&app, &f, CONFIRM, &input).await,
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    let (next, next_code) = prepare(&app, &f).await;
    let retained: Vec<u8> = sqlx::query_scalar(
        "SELECT code_hash FROM auth_passkey_recovery_codes WHERE realm_id=$1 AND user_id=$2",
    )
    .bind(f.auth.realm())
    .bind(f.owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(retained == active);
    let response = send(
        &app,
        &f,
        CONFIRM,
        &json!({"id":next,"code":next_code.expose()}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let rotated: Vec<u8> = sqlx::query_scalar(
        "SELECT code_hash FROM auth_passkey_recovery_codes WHERE realm_id=$1 AND user_id=$2",
    )
    .bind(f.auth.realm())
    .bind(f.owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(rotated == next_code.verifier() && rotated != active);
    let after: (String,String,String) = sqlx::query_as("SELECT u.authentication_policy,s.authentication_method,s.authenticated_at::text FROM auth_users u JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id WHERE u.realm_id=$1 AND u.id=$2 AND s.token_hash=$3")
        .bind(f.auth.realm()).bind(f.owner).bind(f.session.verifier().as_slice()).fetch_one(&pool).await.unwrap();
    assert!(before == after);
    *mail.fail_notices.lock().unwrap() = true;
    assert!(matches!(
        auth.deliver_security_notice().await,
        Err(auth_core::Error::Unavailable)
    ));
    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_security_notifications WHERE realm_id=$1 AND kind='passkey_recovery_changed'").bind(f.auth.realm()).fetch_one(&pool).await.unwrap();
    assert_eq!(queued, 2);
    sqlx::query("UPDATE auth_security_notifications SET next_attempt_at=clock_timestamp() WHERE realm_id=$1").bind(f.auth.realm()).execute(&pool).await.unwrap();
    *mail.fail_notices.lock().unwrap() = false;
    assert!(auth.deliver_security_notice().await.unwrap());
    assert!(auth.deliver_security_notice().await.unwrap());
    assert_eq!(*mail.notices.lock().unwrap(), 2);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn email_free_http_configuration_emits_no_fabricated_notice_or_contact(pool: PgPool) {
    let f = Fixture::new(pool.clone(), true).await;
    let app = app(&f, f.auth.clone());
    let (id, code) = prepare(&app, &f).await;
    assert_eq!(
        send(&app, &f, CONFIRM, &json!({"id":id,"code":code.expose()}))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(!f.auth.deliver_security_notice().await.unwrap());
    assert!(
        f.store
            .authenticate(f.auth.realm(), f.session.verifier())
            .await
            .unwrap()
            .email
            .is_none()
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn persistence_failure_returns_no_saved_code_or_success_cookie_and_confirmation_remains_retryable(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone(), false).await;
    let app = app(&f, f.auth.clone());
    sqlx::raw_sql("CREATE FUNCTION fail_setup_prepare() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled setup write failure'; END $$; CREATE TRIGGER fail_setup_prepare BEFORE INSERT ON auth_passkey_recovery_setups FOR EACH ROW EXECUTE FUNCTION fail_setup_prepare();")
        .execute(&pool).await.unwrap();
    rejected(
        send(&app, &f, PREPARE, &json!({})).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
    sqlx::query("DROP TRIGGER fail_setup_prepare ON auth_passkey_recovery_setups")
        .execute(&pool)
        .await
        .unwrap();
    let (id, code) = prepare(&app, &f).await;
    sqlx::raw_sql("CREATE FUNCTION fail_setup_notice() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled setup notice failure'; END $$; CREATE TRIGGER fail_setup_notice BEFORE INSERT ON auth_security_notifications FOR EACH ROW EXECUTE FUNCTION fail_setup_notice();")
        .execute(&pool).await.unwrap();
    let input = json!({"id":id,"code":code.expose()});
    rejected(
        send(&app, &f, CONFIRM, &input).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
    let active: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_passkey_recovery_codes WHERE realm_id=$1")
            .bind(f.auth.realm())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(active, 0);
    sqlx::query("DROP TRIGGER fail_setup_notice ON auth_security_notifications")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        send(&app, &f, CONFIRM, &input).await.status(),
        StatusCode::NO_CONTENT
    );
}
