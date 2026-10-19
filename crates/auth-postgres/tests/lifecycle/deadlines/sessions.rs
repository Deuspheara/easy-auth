use super::{gates::*, *};
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn session_validation_cannot_revive_idle_or_absolute_expiry_after_unchanged_row_wait(
    pool: PgPool,
) {
    for idle in [true, false] {
        let f = Fixture::new(pool.clone()).await;
        let (update, deadline) = if idle {
            (
                "UPDATE auth_sessions SET last_seen_at=clock_timestamp()-interval '29 minutes 55 seconds' WHERE realm_id=$1",
                "SELECT last_seen_at<=clock_timestamp()-interval '30 minutes' FROM auth_sessions WHERE realm_id=$1",
            )
        } else {
            (
                "UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1",
                "SELECT expires_at<=clock_timestamp() FROM auth_sessions WHERE realm_id=$1",
            )
        };
        sqlx::query(update)
            .bind(f.realm)
            .execute(&pool)
            .await
            .unwrap();
        let before = f.snapshot().await;
        let mut gate = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM auth_sessions WHERE realm_id=$1 FOR UPDATE")
            .bind(f.realm)
            .execute(&mut *gate)
            .await
            .unwrap();
        let store = f.store.clone();
        let current = f.session.verifier();
        let finish = tokio::spawn(async move { store.authenticate(f.realm, current).await });
        wait_and_expire(&pool, "%auth_sessions%", deadline, f.realm).await;
        gate.commit().await.unwrap();
        assert!(
            matches!(finished(finish).await, Err(Error::Unauthorized)),
            "session validation must use time after its row wait"
        );
        f.assert_unchanged(before).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn inventory_cannot_touch_and_list_a_caller_that_expires_during_its_row_wait(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    sqlx::query("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1")
        .bind(f.realm).execute(&pool).await.unwrap();
    let before = f.snapshot().await;
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_sessions WHERE realm_id=$1 FOR UPDATE")
        .bind(f.realm)
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let current = f.session.verifier();
    let finish = tokio::spawn(async move { store.list_sessions(f.realm, current, None).await });
    wait_and_expire(
        &pool,
        "%auth_sessions%",
        "SELECT expires_at<=clock_timestamp() FROM auth_sessions WHERE realm_id=$1",
        f.realm,
    )
    .await;
    gate.commit().await.unwrap();
    assert!(
        matches!(finished(finish).await, Err(Error::Unauthorized)),
        "expired inventory caller cannot commit its touch"
    );
    f.assert_unchanged(before).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn individual_and_all_revocation_cannot_outlive_original_freshness_during_audit(
    pool: PgPool,
) {
    for all in [false, true] {
        let f = Fixture::new(pool.clone()).await;
        let deadline = arm_freshness(&pool, f.realm).await;
        let before = f.snapshot().await;
        let gate = write_gate(
            &pool,
            "auth_audit",
            if all {
                "all_sessions_revoked"
            } else {
                "session_revoked"
            },
        )
        .await;
        let store = f.store.clone();
        let current = f.session.verifier();
        let actor = f.actor;
        let finish = tokio::spawn(async move {
            if all {
                store.revoke_all_sessions(f.realm, current).await
            } else {
                store
                    .revoke_session(f.realm, current, actor)
                    .await
                    .map(|_| ())
            }
        });
        wait_and_expire(&pool, "%INSERT%auth_audit%", &deadline, f.realm).await;
        gate.commit().await.unwrap();
        assert!(
            matches!(finished(finish).await, Err(Error::Unauthorized)),
            "stale revocation authority must roll back"
        );
        f.assert_unchanged(before).await;
    }
}
