use super::setup::{allow_jit, facts, fixture, verify};
use auth_core::{Error, SamlSignIn};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn every_authority_write_failure_rolls_back_replay_identity_session_and_audit(pool: PgPool) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let service = SamlSignIn::new(f.store.clone());
    for table in [
        "auth_saml_replays",
        "auth_users",
        "auth_saml_identities",
        "auth_sessions",
        "auth_audit",
    ] {
        sqlx::raw_sql(&format!("CREATE FUNCTION reject_saml_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned test failure'; END $$; CREATE TRIGGER reject_saml_commit BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION reject_saml_commit();"))
            .execute(&f.pool).await.unwrap();
        assert!(matches!(
            service
                .finish(policy.map(verify(&f, "normal").await).unwrap())
                .await,
            Err(Error::Unavailable)
        ));
        assert_eq!(facts(&f).await, (0, 0, 0, 0, 0));
        sqlx::raw_sql(&format!(
            "DROP TRIGGER reject_saml_commit ON {table}; DROP FUNCTION reject_saml_commit();"
        ))
        .execute(&f.pool)
        .await
        .unwrap();
    }
    assert!(
        service
            .finish(policy.map(verify(&f, "normal").await).unwrap())
            .await
            .is_ok()
    );
    assert_eq!(facts(&f).await, (1, 1, 1, 2, 1));
}
