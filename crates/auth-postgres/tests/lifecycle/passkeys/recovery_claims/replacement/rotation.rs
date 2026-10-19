use super::super::waiting::gate;
use super::*;
use auth_core::{PasskeyRecoverySetupRepository, PasskeyRecoverySetupRequest};
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn committed_code_rotation_rejects_waiting_preverified_recovery_completion(pool: PgPool) {
    for email_free in [true, false] {
        let mut f = Replacement::new(pool.clone(), email_free).await;
        f.mature().await;
        let (id, response) = f.assertion().await;
        let proof = f.proof(id, &response).await;
        let next = f.c.setup.prepare(&f.c.f.session, SOURCE).await.unwrap();
        let barrier = gate(
            &pool,
            "auth_audit",
            "INSERT",
            "NEW.kind='passkey_recovery_configured'",
        )
        .await;
        let observer = observer(&pool).await;
        let rotate = rotation(&f, next.id, next.code.verifier());
        let winner = gated_backend(&observer).await;
        let request = f.request(id);
        let store = f.c.f.store.clone();
        let complete = tokio::spawn(async move {
            store
                .commit_recovery_replacement(&request, proof, [104; 32])
                .await
        });
        blocked_by(&observer, winner).await;
        barrier.commit().await.unwrap();
        finished(rotate).await.unwrap();
        assert!(matches!(finished(complete).await, Err(Error::Unauthorized)));
        observer.close().await;
        drop_gate(&pool).await;

        let facts: (Uuid, bool, i64, i64, i64) = sqlx::query_as(
            "SELECT version,consumed_at IS NULL,
            (SELECT count(*) FROM auth_passkey_recovery_claims WHERE realm_id=$1),
            (SELECT count(*) FROM auth_passkey_recovery_replacements WHERE realm_id=$1),
            (SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovered')
            FROM auth_passkey_recovery_codes WHERE realm_id=$1 AND user_id=$2",
        )
        .bind(f.c.f.realm)
        .bind(f.c.owner)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(facts, (next.id, true, 0, 0, 0));
        assert!(matches!(
            f.c.f.store.authenticate(f.c.f.realm, [104; 32]).await,
            Err(Error::Unauthorized)
        ));
        f.c.f
            .store
            .authenticate(f.c.f.realm, f.c.f.session.verifier())
            .await
            .unwrap();
        // The retained original key still performs a real private-key assertion.
        f.c.f.sign_in_with_key(&mut f.c.token).await;
        let claim =
            f.c.flow
                .begin(f.c.owner, &next.code, &f.c.browser, SOURCE)
                .await
                .unwrap();
        assert_ne!(claim.id, f.target.claim_id);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn committed_recovery_rejects_waiting_configuration_from_revoked_original_session(
    pool: PgPool,
) {
    for email_free in [true, false] {
        let mut f = Replacement::new(pool.clone(), email_free).await;
        f.mature().await;
        let (id, response) = f.assertion().await;
        let proof = f.proof(id, &response).await;
        let next = f.c.setup.prepare(&f.c.f.session, SOURCE).await.unwrap();
        let barrier = gate(
            &pool,
            "auth_audit",
            "INSERT",
            "NEW.kind='passkey_recovered'",
        )
        .await;
        let observer = observer(&pool).await;
        let request = f.request(id);
        let store = f.c.f.store.clone();
        let complete = tokio::spawn(async move {
            store
                .commit_recovery_replacement(&request, proof, [105; 32])
                .await
        });
        let winner = gated_backend(&observer).await;
        let rotate = rotation(&f, next.id, next.code.verifier());
        blocked_by(&observer, winner).await;
        barrier.commit().await.unwrap();
        finished(complete).await.unwrap();
        assert!(matches!(finished(rotate).await, Err(Error::Unauthorized)));
        observer.close().await;
        drop_gate(&pool).await;

        let facts: (bool, bool, i64, i64, i64) = sqlx::query_as(
            "SELECT k.version<>$3,k.consumed_at IS NOT NULL,
            (SELECT count(*) FROM auth_passkey_recovery_setups WHERE realm_id=$1),
            (SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovery_configured'),
            (SELECT count(*) FROM auth_sessions WHERE realm_id=$1 AND revoked_at IS NULL)
            FROM auth_passkey_recovery_codes k WHERE realm_id=$1 AND user_id=$2",
        )
        .bind(f.c.f.realm)
        .bind(f.c.owner)
        .bind(next.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(facts, (true, true, 0, 1, 1));
        assert!(matches!(
            f.c.f
                .store
                .authenticate(f.c.f.realm, f.c.f.session.verifier())
                .await,
            Err(Error::Unauthorized)
        ));
        f.c.f
            .store
            .authenticate(f.c.f.realm, [105; 32])
            .await
            .unwrap();
        let before = f.c.snapshot().await;
        assert!(matches!(
            f.c.setup
                .confirm(&f.c.f.session, SOURCE, next.id, &next.code)
                .await,
            Err(Error::Unauthorized)
        ));
        f.c.unchanged(before).await;
    }
}

fn rotation(
    f: &Replacement,
    id: Uuid,
    code: auth_core::Verifier,
) -> tokio::task::JoinHandle<auth_core::Result<()>> {
    let request = PasskeyRecoverySetupRequest {
        realm: f.c.f.realm,
        session: f.c.f.session.verifier(),
        rp_id: f.c.f.service.rp_id().into(),
        source: [106; 32],
    };
    let store = f.c.f.store.clone();
    tokio::spawn(async move {
        store
            .confirm_passkey_recovery_code(&request, id, code)
            .await
    })
}

async fn observer(pool: &PgPool) -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: rotation race observer connection")
}

async fn gated_backend(observer: &PgPool) -> i32 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar(
                "SELECT pid FROM pg_locks WHERE locktype='advisory' AND objid=200041
                AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())",
            ).fetch_optional(observer).await.unwrap();
            if let Some(pid) = pid { return pid; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: winner must reach final audit with owner held")
}

async fn blocked_by(observer: &PgPool, winner: i32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
                AND $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(winner)
            .fetch_one(observer)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("test infrastructure: contender must wait on actual winner before release");
}

async fn finished(task: tokio::task::JoinHandle<auth_core::Result<()>>) -> auth_core::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("test infrastructure: race must finish after releasing the gate")
        .expect("test infrastructure: race task must not panic")
}

async fn drop_gate(pool: &PgPool) {
    sqlx::query("DROP TRIGGER recovery_claim_gate ON auth_audit")
        .execute(pool)
        .await
        .unwrap();
}
