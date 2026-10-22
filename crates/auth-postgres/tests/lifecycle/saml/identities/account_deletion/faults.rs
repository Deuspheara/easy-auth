use super::setup::{Fixture, counts, proof};
use auth_core::{Error, Repository, SamlAccountDeletion};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn every_erasure_tail_failure_rolls_back_replay_user_session_audit_cooldown_and_notice(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    sqlx::query("UPDATE auth_users SET email='stored-contact@example.test',email_verified_at=clock_timestamp() WHERE realm_id=$1 AND id=$2")
        .bind(f.user.realm_id).bind(f.user.id).execute(&f.source.pool).await.unwrap();
    for (table, event, condition) in [
        ("auth_users", "DELETE", ""),
        ("auth_saml_deleted_subjects", "INSERT", ""),
        ("auth_audit", "INSERT", "WHEN (NEW.kind='account_deleted')"),
        ("auth_security_notifications", "INSERT", ""),
    ] {
        let deletion = proof(&f, "normal").await;
        sqlx::raw_sql(&format!("CREATE FUNCTION reject_saml_erasure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned fixture storage failure'; END $$; CREATE TRIGGER reject_saml_erasure BEFORE {event} ON {table} FOR EACH ROW {condition} EXECUTE FUNCTION reject_saml_erasure();"))
            .execute(&f.source.pool).await.unwrap();
        assert!(
            matches!(
                SamlAccountDeletion::new(f.source.store.clone())
                    .finish(deletion)
                    .await,
                Err(Error::Unavailable)
            ),
            "storage failure in {table} must not become an authentication denial"
        );
        assert_eq!(
            counts(&f).await,
            (1, 1, 1, 2, 1, 0),
            "all authority writes roll back in {table}; consumed preparation stays consumed"
        );
        let state: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_saml_deleted_subjects),(SELECT count(*) FROM auth_security_notifications),(SELECT count(*) FROM auth_audit WHERE NOT subject_erased AND user_id=$1)")
            .bind(f.user.id).fetch_one(&f.source.pool).await.unwrap();
        assert_eq!(state, (0, 0, 1));
        sqlx::raw_sql(&format!(
            "DROP TRIGGER reject_saml_erasure ON {table}; DROP FUNCTION reject_saml_erasure();"
        ))
        .execute(&f.source.pool)
        .await
        .unwrap();
        f.source
            .store
            .authenticate(f.user.realm_id, f.current.verifier())
            .await
            .unwrap();
    }
    SamlAccountDeletion::new(f.source.store.clone())
        .finish(proof(&f, "normal").await)
        .await
        .unwrap();
    assert_eq!(counts(&f).await, (0, 0, 0, 4, 2, 0));
}
