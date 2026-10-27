use super::super::setup::Fixture;
use super::*;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn missing_vault_and_audit_failure_cannot_commit_identity_session_or_grant(pool: PgPool) {
    let f = Fixture::new(pool.clone(), AppleClientType::Web, OidcJitPolicy::Allow).await;
    let a = f.prepare("no-config", serde_json::json!({})).await;
    let bare = Arc::new(easy_auth_postgres::Postgres::new(pool));
    let result = AppleGrantSignIn::new(bare)
        .finish(captured(&f, &a).await.unwrap())
        .await;
    assert!(matches!(result, Err(Error::Unavailable)));
    for table in ["auth_oidc_identities", "auth_sessions", "auth_apple_grants"] {
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE realm_id=$1"))
                .bind(f.realm())
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
    }
    sqlx::raw_sql("CREATE FUNCTION reject_grant_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned grant audit fault'; END $$; CREATE TRIGGER reject_grant_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION reject_grant_audit();").execute(&f.pool).await.unwrap();
    let a = f.prepare("audit-fault", serde_json::json!({})).await;
    assert!(matches!(
        AppleGrantSignIn::new(f.store.clone())
            .finish(captured(&f, &a).await.unwrap())
            .await,
        Err(Error::Unavailable)
    ));
    assert!(envelopes(&f).await.is_empty());
    sqlx::query("DROP TRIGGER reject_grant_audit ON auth_audit")
        .execute(&f.pool)
        .await
        .unwrap();
    sign_in(&f, "valid-after-fault").await;
    assert_eq!(envelopes(&f).await.len(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_unlink_audit_rolls_back_job_transition_and_identity_removal(pool: PgPool) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let (owner, current) = local(&f).await;
    let linked = link(&f, &owner, &current, "rollback-grant").await;
    sqlx::raw_sql("CREATE FUNCTION reject_unlink_grant_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='oidc_identity_unlinked' THEN RAISE EXCEPTION 'owned unlink grant fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_unlink_grant_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION reject_unlink_grant_audit();").execute(&f.pool).await.unwrap();
    let result = OidcIdentityLinking::new(f.store.clone())
        .unlink(f.realm(), &current, linked.id)
        .await;
    assert!(matches!(result, Err(Error::Unavailable)));
    let (state, identity): (String, Option<Uuid>) =
        sqlx::query_as("SELECT state,identity_id FROM auth_apple_grants WHERE realm_id=$1")
            .bind(f.realm())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(state, "active");
    assert_eq!(identity, Some(linked.id));
    sqlx::query("DROP TRIGGER reject_unlink_grant_audit ON auth_audit")
        .execute(&f.pool)
        .await
        .unwrap();
    OidcIdentityLinking::new(f.store.clone())
        .unlink(f.realm(), &current, linked.id)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn foreign_source_binding_cannot_seal_and_foreign_realm_has_no_grant_rows(pool: PgPool) {
    let f = Fixture::new(pool.clone(), AppleClientType::Web, OidcJitPolicy::Allow).await;
    let foreign = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let a = f.prepare("sealed-source", serde_json::json!({})).await;
    let (_, capture) = captured(&f, &a).await.unwrap().into_parts();
    let c = foreign.policy.configuration();
    let binding = AppleGrantBinding::new(
        c.realm(),
        c.connection(),
        c.client(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .unwrap();
    assert!(matches!(
        capture.seal(binding, &foreign.vault).await,
        Err(Error::Unauthorized)
    ));
    assert!(envelopes(&foreign).await.is_empty());
    let (user, _) = sign_in(&f, "owned").await;
    assert_eq!(user.realm_id, f.realm());
    let envelope = envelopes(&f).await.pop().unwrap();
    assert!(matches!(
        new_vault().rewrap(&envelope).await,
        Err(Error::Unavailable)
    ));
}
