use super::*;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn failed_completion_audit_or_notice_preserves_keys_sessions_code_and_candidate(
    pool: PgPool,
) {
    for table in ["auth_audit", "auth_security_notifications"] {
        let mut f = Replacement::new(pool.clone(), false).await;
        f.mature().await;
        let (id, response) = f.assertion().await;
        sqlx::raw_sql(&format!("CREATE OR REPLACE FUNCTION reject_recovery_completion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test infrastructure: deliberate write failure'; END $$; CREATE TRIGGER reject_recovery_completion BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION reject_recovery_completion();")).execute(&pool).await.unwrap();
        let before = f.c.snapshot().await;
        assert!(
            matches!(
                f.flow
                    .finish(f.target, id, &f.c.browser, SOURCE, &response)
                    .await,
                Err(Error::Unavailable)
            ),
            "storage failure must not pretend authority rejection or success"
        );
        f.c.unchanged(before).await;
        sqlx::query(&format!(
            "DROP TRIGGER reject_recovery_completion ON {table}"
        ))
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            f.flow
                .finish(f.target, id, &f.c.browser, SOURCE, &response)
                .await
                .is_ok()
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn competing_valid_assertions_have_one_completion_and_no_second_session(pool: PgPool) {
    let mut f = Replacement::new(pool.clone(), true).await;
    f.mature().await;
    let (id, response) = f.assertion().await;
    let first = f.proof(id, &response).await;
    let second = f.proof(id, &response).await;
    let request = f.request(id);
    let (a, b) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            f.c.f
                .store
                .commit_recovery_replacement(&request, first, [61; 32]),
            f.c.f
                .store
                .commit_recovery_replacement(&request, second, [62; 32])
        )
    })
    .await
    .expect("test infrastructure: completion race must not deadlock");
    assert!(matches!(
        (&a, &b),
        (Ok(()), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(()))
    ));
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovered'),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1 AND revoked_at IS NULL)").bind(f.c.f.realm).fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (1, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn cancellation_and_completion_race_has_one_terminal_winner(pool: PgPool) {
    let mut f = Replacement::new(pool.clone(), true).await;
    f.mature().await;
    let (id, response) = f.assertion().await;
    let proof = f.proof(id, &response).await;
    let request = f.request(id);
    let (complete, cancel) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            f.c.f
                .store
                .commit_recovery_replacement(&request, proof, [67; 32]),
            f.c.f
                .store
                .cancel_passkey_recovery_claim(&request.claim, request.claim_id)
        )
    })
    .await
    .expect("test infrastructure: cancellation race must not deadlock");
    assert!(matches!(
        (&complete, &cancel),
        (Ok(()), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(()))
    ));
    let terminal:(bool,bool)=sqlx::query_as("SELECT completed_at IS NOT NULL,cancelled_at IS NOT NULL FROM auth_passkey_recovery_claims WHERE realm_id=$1").bind(f.c.f.realm).fetch_one(&pool).await.unwrap();
    assert_ne!(terminal.0, terminal.1);
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_passkey_recovery_replacements WHERE realm_id=$1",
    )
    .bind(f.c.f.realm)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn rp_wide_candidate_collision_preserves_other_realm_and_original_authority(pool: PgPool) {
    let mut f = Replacement::new(pool.clone(), true).await;
    f.mature().await;
    let (id, response) = f.assertion().await;
    let proof = f.proof(id, &response).await;
    let realm = Uuid::new_v4();
    let peer = Uuid::new_v4();
    f.c.f.store.ensure_realm(realm).await.unwrap();
    sqlx::query(
        "INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,'collision@example.test')",
    )
    .bind(realm)
    .bind(peer)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO auth_passkeys(realm_id,id,user_id,rp_id,credential_id,credential,label) VALUES ($1,$2,$3,$4,$5,$6,'Peer')")
        .bind(realm).bind(Uuid::new_v4()).bind(peer).bind(proof.rp_id()).bind(proof.credential_id()).bind(proof.expected_credential_for_database()).execute(&pool).await.unwrap();
    let before = f.c.snapshot().await;
    assert!(matches!(
        f.c.f
            .store
            .commit_recovery_replacement(&f.request(id), proof, [68; 32])
            .await,
        Err(Error::Unauthorized)
    ));
    f.c.unchanged(before).await;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE realm_id=$1 AND user_id=$2")
            .bind(realm)
            .bind(peer)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn mailbox_proof_lock_order_precedes_owner_in_recovery_completion(pool: PgPool) {
    let mut f = Replacement::new(pool.clone(), false).await;
    f.mature().await;
    let (id, response) = f.assertion().await;
    let proof = f.proof(id, &response).await;
    let mut consumer = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':' || 'alice@example.com',0))")
        .bind(f.c.f.realm).execute(&mut *consumer).await.unwrap();
    let store = f.c.f.store.clone();
    let request = f.request(id);
    let action = tokio::spawn(async move {
        store
            .commit_recovery_replacement(&request, proof, [73; 32])
            .await
    });
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: mailbox lock observer");
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT pg_advisory_xact_lock(hashtextextended%')")
                .fetch_one(&observer).await.unwrap();
            if waiting {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: completion must reach email-before-owner lock");
    sqlx::query("SET LOCAL statement_timeout='1s'")
        .execute(&mut *consumer)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(f.c.f.realm)
        .bind(f.c.owner)
        .execute(&mut *consumer)
        .await
        .expect("completion must not hold owner while waiting on mailbox consumer");
    consumer.commit().await.unwrap();
    observer.close().await;
    tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
