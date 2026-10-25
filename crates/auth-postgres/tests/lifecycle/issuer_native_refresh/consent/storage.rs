use super::*;

#[sqlx::test]
async fn native_preparation_and_final_audit_faults_roll_back_every_new_authority_row(pool: PgPool) {
    let f = Fixture::new(pool).await;
    sqlx::raw_sql("ALTER TABLE auth_issuer_native_consents ADD CONSTRAINT owned_native_fault CHECK (false) NOT VALID").execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.prepare_with("openid offline_access", "consent").await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    sqlx::raw_sql("ALTER TABLE auth_issuer_native_consents DROP CONSTRAINT owned_native_fault")
        .execute(&f.pool)
        .await
        .unwrap();
    let pending = f.prepare().await;
    sqlx::raw_sql("ALTER TABLE auth_audit ADD CONSTRAINT owned_native_audit_fault CHECK (kind<>'issuer_authorized') NOT VALID").execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.service
            .approve(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.facts().await, (1, 1, 0, 0, 0));
    let pending_state:bool=sqlx::query_scalar("SELECT a.status='pending' AND a.code_hash IS NULL AND c.approved_at_us IS NULL FROM auth_issuer_authorizations a JOIN auth_issuer_native_consents c ON (a.realm_id,a.id)=(c.realm_id,c.authorization_id)")
        .fetch_one(&f.pool).await.unwrap();
    assert!(pending_state);
    sqlx::raw_sql("ALTER TABLE auth_audit DROP CONSTRAINT owned_native_audit_fault")
        .execute(&f.pool)
        .await
        .unwrap();
    f.service
        .approve(
            &f.current,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        )
        .await
        .unwrap();
    let attributed:bool=sqlx::query_scalar("SELECT user_id=$1 AND actor_session_id IS NOT NULL AND issuer_client_id=$2 AND issuer_authorization_id=$3 FROM auth_audit WHERE kind='issuer_authorized'")
        .bind(f.owner).bind(f.policy.client().client()).bind(pending.authorization()).fetch_one(&f.pool).await.unwrap();
    assert!(attributed);
}

#[sqlx::test]
async fn native_consent_constraints_keep_full_tuple_and_proposed_caps_then_cascade_on_erasure(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let pending = f.prepare().await;
    for change in [
        "native_refresh=false",
        "user_id='00000000-0000-0000-0000-000000000001'",
        "client_id='00000000-0000-0000-0000-000000000001'",
        "grant_expires_at_us=source_absolute_cap_us+1",
        "approved_at_us=prepared_at_us-1",
        "idle_seconds=lifetime_seconds+1",
    ] {
        assert!(
            sqlx::raw_sql(&format!("UPDATE auth_issuer_native_consents SET {change}"))
                .execute(&f.pool)
                .await
                .is_err()
        );
    }
    assert!(
        sqlx::raw_sql("UPDATE auth_issuer_authorizations SET native_refresh=false")
            .execute(&f.pool)
            .await
            .is_err()
    );
    f.service
        .approve(
            &f.current,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        )
        .await
        .unwrap();
    // Actual account erasure uses the existing fresh-session account port.
    let token = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    f.store
        .begin_account_deletion(
            f.policy.authority().realm(),
            f.current.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    f.store
        .finish_account_deletion(
            f.policy.authority().realm(),
            f.current.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
}
