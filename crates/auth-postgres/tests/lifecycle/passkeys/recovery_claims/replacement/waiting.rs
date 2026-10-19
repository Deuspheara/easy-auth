use super::super::waiting::{cross_deadline, gate, rejected_action};
use super::*;

#[sqlx::test(migrations = "./migrations")]
async fn recovery_final_writes_cannot_outlive_original_claim_or_candidate(pool: PgPool) {
    for mode in ["audit_candidate", "notice_claim", "consumption_candidate"] {
        let mut f = Replacement::new(pool.clone(), false).await;
        f.mature().await;
        let (id, response) = f.assertion().await;
        let proof = f.proof(id, &response).await;
        let query = if mode == "notice_claim" {
            sqlx::query("UPDATE auth_passkey_recovery_claims SET expires_at=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1").bind(f.c.f.realm).execute(&pool).await.unwrap();
            "SELECT expires_at<=clock_timestamp() FROM auth_passkey_recovery_claims WHERE realm_id=$1"
        } else {
            sqlx::query("UPDATE auth_passkey_recovery_replacements SET expires_at=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1").bind(f.c.f.realm).execute(&pool).await.unwrap();
            "SELECT expires_at<=clock_timestamp() FROM auth_passkey_recovery_replacements WHERE realm_id=$1"
        };
        let (table, event, condition) = match mode {
            "audit_candidate" => ("auth_audit", "INSERT", "NEW.kind='passkey_recovered'"),
            "notice_claim" => (
                "auth_security_notifications",
                "INSERT",
                "NEW.kind='passkey_recovery_completed'",
            ),
            _ => ("auth_passkey_recovery_replacements", "DELETE", "true"),
        };
        let before = f.c.snapshot().await;
        let gate = gate(&pool, table, event, condition).await;
        let request = f.request(id);
        let store = f.c.f.store.clone();
        let action = tokio::spawn(async move {
            store
                .commit_recovery_replacement(&request, proof, [18; 32])
                .await
        });
        cross_deadline(&pool, f.c.f.realm, query).await;
        gate.commit().await.unwrap();
        rejected_action(action).await;
        f.c.unchanged(before).await;
        sqlx::query(&format!("DROP TRIGGER recovery_claim_gate ON {table}"))
            .execute(&pool)
            .await
            .unwrap();
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_advance_rolls_back_if_its_final_write_outlives_ceremony(pool: PgPool) {
    let mut f = Replacement::new(pool.clone(), true).await;
    f.mature().await;
    let (id, response) = f.registration().await;
    sqlx::query("UPDATE auth_passkey_recovery_replacements SET expires_at=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1").bind(f.c.f.realm).execute(&pool).await.unwrap();
    let before = f.c.snapshot().await;
    let gate = gate(
        &pool,
        "auth_passkey_recovery_replacements",
        "UPDATE",
        "NEW.stage='assertion'",
    )
    .await;
    let action = f
        .flow
        .finish_registration(f.target, id, &f.c.browser, SOURCE, &response);
    let release = async {
        cross_deadline(&pool,f.c.f.realm,"SELECT expires_at<=clock_timestamp() FROM auth_passkey_recovery_replacements WHERE realm_id=$1").await;
        gate.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(action, release);
    assert!(matches!(result, Err(Error::Unauthorized)));
    f.c.unchanged(before).await;
}
