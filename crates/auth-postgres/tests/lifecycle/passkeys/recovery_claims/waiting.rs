use super::*;
use auth_core::PasskeyRecoverySetupRepository;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn claim_creation_and_cancellation_roll_back_when_final_audit_wait_outlives_authority(
    pool: PgPool,
) {
    for mode in ["begin", "browser_cancel", "code_cancel", "key_cancel"] {
        let f = Claims::new(pool.clone(), false).await;
        let id = if mode == "begin" {
            sqlx::raw_sql("CREATE TABLE test_recovery_clock(realm_id uuid PRIMARY KEY,expires_at timestamptz NOT NULL);")
                .execute(&pool).await.unwrap();
            sqlx::query("INSERT INTO test_recovery_clock VALUES ($1,clock_timestamp()+interval '5 seconds')").bind(f.f.realm).execute(&pool).await.unwrap();
            sqlx::raw_sql("CREATE FUNCTION shorten_recovery_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.expires_at=(SELECT expires_at FROM test_recovery_clock WHERE realm_id=NEW.realm_id); RETURN NEW; END $$; CREATE TRIGGER shorten_recovery_claim BEFORE INSERT ON auth_passkey_recovery_claims FOR EACH ROW EXECUTE FUNCTION shorten_recovery_claim();")
                .execute(&pool).await.unwrap();
            Uuid::new_v4()
        } else {
            f.flow
                .begin(f.owner, &f.code, &f.browser, SOURCE)
                .await
                .unwrap()
                .id
        };
        let query = match mode {
            "begin" => {
                "SELECT expires_at<=clock_timestamp() FROM test_recovery_clock WHERE realm_id=$1"
            }
            "browser_cancel" | "code_cancel" => {
                sqlx::query("UPDATE auth_passkey_recovery_claims SET expires_at=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1").bind(f.f.realm).execute(&pool).await.unwrap();
                "SELECT expires_at<=clock_timestamp() FROM auth_passkey_recovery_claims WHERE realm_id=$1"
            }
            "key_cancel" => {
                sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 55 seconds' WHERE realm_id=$1 AND token_hash=$2")
                    .bind(f.f.realm).bind(f.f.session.verifier().as_slice()).execute(&pool).await.unwrap();
                "SELECT authenticated_at<=clock_timestamp()-interval '5 minutes' FROM auth_sessions WHERE realm_id=$1 AND authentication_method='passkey'"
            }
            _ => unreachable!(),
        };
        let snapshot = f.snapshot().await;
        let condition = if mode == "begin" {
            "NEW.kind='passkey_recovery_started'"
        } else {
            "NEW.kind='passkey_recovery_cancelled'"
        };
        let gate = gate(&pool, "auth_audit", "INSERT", condition).await;
        let store = f.f.store.clone();
        let request = f.request();
        let code = f.code.verifier();
        let session = f.f.session.verifier();
        let action = tokio::spawn(async move {
            match mode {
                "begin" => store
                    .begin_passkey_recovery_claim(&request, id, code)
                    .await
                    .map(|_| ()),
                "browser_cancel" => store.cancel_passkey_recovery_claim(&request, id).await,
                "code_cancel" => {
                    store
                        .cancel_passkey_recovery_with_code(
                            &auth_core::PasskeyRecoveryCodeCancellation {
                                realm: request.realm,
                                user_id: request.user_id,
                                rp_id: request.rp_id,
                                source: request.source,
                                code,
                            },
                        )
                        .await
                }
                _ => {
                    store
                        .cancel_passkey_recovery_with_key(
                            &auth_core::PasskeyRecoveryKeyCancellation {
                                realm: request.realm,
                                rp_id: request.rp_id,
                                source: request.source,
                                session,
                            },
                            id,
                        )
                        .await
                }
            }
        });
        cross_deadline(&pool, f.f.realm, query).await;
        gate.commit().await.unwrap();
        rejected_action(action).await;
        f.unchanged(snapshot).await;
        sqlx::query("DROP TRIGGER recovery_claim_gate ON auth_audit")
            .execute(&pool)
            .await
            .unwrap();
        if mode == "begin" {
            sqlx::query("DROP TRIGGER shorten_recovery_claim ON auth_passkey_recovery_claims")
                .execute(&pool)
                .await
                .unwrap();
        }
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn receipt_cannot_commit_after_lease_or_claim_expiry_during_a_final_write(pool: PgPool) {
    for lease_expiry in [true, false] {
        let f = Claims::new(pool.clone(), false).await;
        f.flow
            .begin(f.owner, &f.code, &f.browser, SOURCE)
            .await
            .unwrap();
        let notice = f.start_notice().await;
        let (table, event, condition, query) = if lease_expiry {
            sqlx::query("UPDATE auth_security_notifications SET lease_until=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1 AND id=$2")
                .bind(f.f.realm).bind(notice.id).execute(&pool).await.unwrap();
            (
                "auth_security_notifications",
                "DELETE",
                "OLD.kind='passkey_recovery_started'",
                "SELECT lease_until<=clock_timestamp() FROM auth_security_notifications WHERE realm_id=$1",
            )
        } else {
            sqlx::query("UPDATE auth_passkey_recovery_claims SET expires_at=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1")
                .bind(f.f.realm).execute(&pool).await.unwrap();
            (
                "auth_passkey_recovery_claims",
                "UPDATE",
                "NEW.notified_at IS NOT NULL",
                "SELECT expires_at<=clock_timestamp() FROM auth_passkey_recovery_claims WHERE realm_id=$1",
            )
        };
        let snapshot = f.snapshot().await;
        let gate = gate(&pool, table, event, condition).await;
        let store = f.f.store.clone();
        let realm = f.f.realm;
        let action = tokio::spawn(async move {
            store
                .complete_security_notice(realm, notice.id, notice.lease, true)
                .await
        });
        cross_deadline(&pool, f.f.realm, query).await;
        gate.commit().await.unwrap();
        rejected_action(action).await;
        f.unchanged(snapshot).await;
        f.unnotified().await;
        sqlx::raw_sql(&format!("DROP TRIGGER recovery_claim_gate ON {table}"))
            .execute(&pool)
            .await
            .unwrap();
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_configuration_cannot_rotate_a_code_or_cancel_claim_during_notice_cascade_wait(
    pool: PgPool,
) {
    let f = Claims::new(pool.clone(), false).await;
    f.flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    let pending = f.setup.prepare(&f.f.session, SOURCE).await.unwrap();
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 55 seconds' WHERE realm_id=$1 AND token_hash=$2")
        .bind(f.f.realm).bind(f.f.session.verifier().as_slice()).execute(&pool).await.unwrap();
    let snapshot = f.snapshot().await;
    let gate = gate(
        &pool,
        "auth_security_notifications",
        "DELETE",
        "OLD.kind='passkey_recovery_started'",
    )
    .await;
    let request = auth_core::PasskeyRecoverySetupRequest {
        realm: f.f.realm,
        rp_id: f.f.service.rp_id().into(),
        session: f.f.session.verifier(),
        source: [31; 32],
    };
    let store = f.f.store.clone();
    let hash = pending.code.verifier();
    let action = tokio::spawn(async move {
        store
            .confirm_passkey_recovery_code(&request, pending.id, hash)
            .await
    });
    cross_deadline(&pool,f.f.realm,"SELECT authenticated_at<=clock_timestamp()-interval '5 minutes' FROM auth_sessions WHERE realm_id=$1 AND authentication_method='passkey'").await;
    gate.commit().await.unwrap();
    rejected_action(action).await;
    f.unchanged(snapshot).await;
}

async fn gate(
    pool: &PgPool,
    table: &str,
    event: &str,
    condition: &str,
) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(200041)")
        .execute(&mut *gate)
        .await
        .unwrap();
    let returned = if event == "DELETE" { "OLD" } else { "NEW" };
    // All identifiers/conditions come from the fixed test matrix above.
    sqlx::raw_sql(&format!("CREATE OR REPLACE FUNCTION recovery_claim_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {condition} THEN PERFORM pg_advisory_xact_lock(200041); END IF; RETURN {returned}; END $$; CREATE TRIGGER recovery_claim_gate BEFORE {event} ON {table} FOR EACH ROW EXECUTE FUNCTION recovery_claim_gate();"))
        .execute(pool).await.unwrap();
    gate
}

async fn cross_deadline(pool: &PgPool, realm: Uuid, query: &str) {
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: claim observer connection");
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=200041 AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))")
                .fetch_one(&observer).await.unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: claim operation must reach its gate");
    assert!(
        !sqlx::query_scalar::<_, bool>(query)
            .bind(realm)
            .fetch_one(&observer)
            .await
            .unwrap(),
        "test infrastructure: wait must precede expiry"
    );
    tokio::time::timeout(Duration::from_secs(8), async {
        while !sqlx::query_scalar::<_, bool>(query)
            .bind(realm)
            .fetch_one(&observer)
            .await
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("test infrastructure: claim database deadline crossing");
    observer.close().await;
}

async fn rejected_action(action: tokio::task::JoinHandle<auth_core::Result<()>>) {
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("test infrastructure: claim completion")
        .unwrap();
    assert!(
        matches!(result, Err(Error::Unauthorized)),
        "infrastructure errors do not prove expired-authority rejection"
    );
}
