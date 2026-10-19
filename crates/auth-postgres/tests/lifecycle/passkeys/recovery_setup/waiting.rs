use super::*;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn setup_cannot_outlive_original_authentication_or_proof_during_final_writes(pool: PgPool) {
    for surface in ["prepare", "audit", "notice", "consume"] {
        let f = Setup::new(pool.clone(), false).await;
        let first = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
        f.flow
            .confirm(&f.f.session, SOURCE, first.id, &first.code)
            .await
            .unwrap();
        let pending = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
        let proof_expiry = surface == "consume";
        let expired_query = if proof_expiry {
            sqlx::query("UPDATE auth_passkey_recovery_setups SET expires_at=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1")
                .bind(f.f.realm).execute(&pool).await.unwrap();
            "SELECT expires_at<=clock_timestamp() FROM auth_passkey_recovery_setups WHERE realm_id=$1"
        } else {
            sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 55 seconds' WHERE realm_id=$1 AND token_hash=$2")
                .bind(f.f.realm).bind(f.f.session.verifier().as_slice()).execute(&pool).await.unwrap();
            "SELECT authenticated_at<=clock_timestamp()-interval '5 minutes' FROM auth_sessions WHERE realm_id=$1 AND authentication_method='passkey'"
        };
        let snapshot = f.snapshot().await;
        let (table, event, condition, returned) = match surface {
            "prepare" => ("auth_passkey_recovery_setups", "INSERT", "true", "NEW"),
            "audit" => (
                "auth_audit",
                "INSERT",
                "NEW.kind='passkey_recovery_configured'",
                "NEW",
            ),
            "notice" => (
                "auth_security_notifications",
                "INSERT",
                "NEW.kind='passkey_recovery_changed'",
                "NEW",
            ),
            "consume" => ("auth_passkey_recovery_setups", "DELETE", "true", "OLD"),
            _ => unreachable!(),
        };
        let mut gate = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(200031)")
            .execute(&mut *gate)
            .await
            .unwrap();
        // Fixed test-only identifiers and trigger condition; no request data.
        sqlx::raw_sql(&format!("CREATE OR REPLACE FUNCTION recovery_setup_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {condition} THEN PERFORM pg_advisory_xact_lock(200031); END IF; RETURN {returned}; END $$; CREATE TRIGGER recovery_setup_gate BEFORE {event} ON {table} FOR EACH ROW EXECUTE FUNCTION recovery_setup_gate();"))
            .execute(&pool).await.unwrap();
        let store = f.f.store.clone();
        let request = f.request();
        let id = pending.id;
        let hash = pending.code.verifier();
        let action = tokio::spawn(async move {
            if surface == "prepare" {
                store
                    .prepare_passkey_recovery_code(&request, Uuid::new_v4(), hash)
                    .await
            } else {
                store
                    .confirm_passkey_recovery_code(&request, id, hash)
                    .await
            }
        });
        observe_expiry(&pool, f.f.realm, expired_query).await;
        gate.commit().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), action)
            .await
            .expect("test infrastructure: setup action completion")
            .unwrap();
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "{surface}: infrastructure errors cannot satisfy deadline rejection"
        );
        f.unchanged(snapshot).await;
        sqlx::raw_sql(&format!("DROP TRIGGER recovery_setup_gate ON {table}"))
            .execute(&pool)
            .await
            .unwrap();
    }
}

async fn observe_expiry(pool: &PgPool, realm: Uuid, query: &str) {
    // Avoid SQLx's shared parent permits while the gate/action own connections.
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: setup observer connection");
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=200031 AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))")
                .fetch_one(&observer).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: setup action must reach the expected gate");
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
    .expect("test infrastructure: setup database deadline crossing");
    observer.close().await;
}
