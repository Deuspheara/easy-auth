use super::*;

#[sqlx::test(migrations = "./migrations")]
async fn repeated_preparation_and_competing_confirmation_have_one_exact_winner(pool: PgPool) {
    let f = Setup::new(pool, false).await;
    let old = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
    let current = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
    assert!(matches!(
        f.flow
            .confirm(&f.f.session, SOURCE, old.id, &old.code)
            .await,
        Err(Error::Unauthorized)
    ));
    let (a, b) = tokio::join!(
        f.flow
            .confirm(&f.f.session, SOURCE, current.id, &current.code),
        f.flow
            .confirm(&f.f.session, SOURCE, current.id, &current.code)
    );
    assert!(
        matches!(
            (&a, &b),
            (Ok(()), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(()))
        ),
        "infrastructure failures are not accepted race losers"
    );
    assert_eq!(f.counts().await, (0, 1, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn audit_or_notification_failure_keeps_prior_code_and_confirmation_retryable(pool: PgPool) {
    let f = Setup::new(pool.clone(), false).await;
    let first = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
    f.flow
        .confirm(&f.f.session, SOURCE, first.id, &first.code)
        .await
        .unwrap();
    let replacement = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
    let snapshot = f.snapshot().await;
    for (table, kind) in [
        ("auth_audit", "passkey_recovery_configured"),
        ("auth_security_notifications", "passkey_recovery_changed"),
    ] {
        sqlx::raw_sql(&format!("CREATE OR REPLACE FUNCTION fail_recovery_setup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='{kind}' THEN RAISE EXCEPTION 'controlled setup failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_recovery_setup BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION fail_recovery_setup();"))
            .execute(&pool).await.unwrap();
        assert!(matches!(
            f.flow
                .confirm(&f.f.session, SOURCE, replacement.id, &replacement.code)
                .await,
            Err(Error::Unavailable)
        ));
        f.unchanged(snapshot.clone()).await;
        sqlx::raw_sql(&format!("DROP TRIGGER fail_recovery_setup ON {table}"))
            .execute(&pool)
            .await
            .unwrap();
    }
    f.flow
        .confirm(&f.f.session, SOURCE, replacement.id, &replacement.code)
        .await
        .unwrap();
    assert_eq!(f.counts().await, (0, 2, 2));
}
