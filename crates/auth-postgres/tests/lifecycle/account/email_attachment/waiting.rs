use super::*;
use auth_core::Error;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn initiation_cannot_send_a_new_proof_after_waiting_past_original_freshness(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let _ = f.proof("old@example.com").await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 55 seconds' WHERE id=$1")
        .bind(f.actor).execute(&f.pool).await.unwrap();
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT user_id FROM auth_email_attachments WHERE user_id=$1 FOR UPDATE")
        .bind(f.user)
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let realm = f.realm;
    let current = f.current.verifier();
    let begin = tokio::spawn(async move {
        store
            .begin_email_attachment(realm, current, "new@example.com", [1; 32], [2; 32])
            .await
    });
    wait_for_lock(&f.pool, "%INSERT INTO auth_email_attachments%").await;
    wait_until(&f.pool,"SELECT authenticated_at<=clock_timestamp()-interval '5 minutes' FROM auth_sessions WHERE id=$1",f.actor).await;
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), begin)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    let target: String =
        sqlx::query_scalar("SELECT email FROM auth_email_attachments WHERE user_id=$1")
            .bind(f.user)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(target, "old@example.com");
    assert_eq!(f.email().await, None);
}

#[sqlx::test(migrations = "./migrations")]
async fn authentication_is_revalidated_after_an_observed_owner_lock_wait(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (proof, browser) = f.proof("contact@example.com").await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(f.realm)
        .bind(f.user)
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let realm = f.realm;
    let current = f.current.verifier();
    let finish = tokio::spawn(async move {
        store
            .finish_email_attachment(
                realm,
                current,
                proof.verifier(),
                browser.verifier(),
                [8; 32],
            )
            .await
    });
    wait_for_lock(
        &f.pool,
        "%SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 AND email IS NULL%FOR UPDATE%",
    )
    .await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE id=$1")
        .bind(f.actor).execute(&mut *gate).await.unwrap();
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), finish)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.email().await, None);
    assert_eq!(f.audits().await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_proof_is_rechecked_after_an_unchanged_proof_row_wait(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (proof, browser) = f.proof("contact@example.com").await;
    sqlx::query("UPDATE auth_email_attachments SET expires_at=clock_timestamp()+interval '5 seconds' WHERE user_id=$1")
        .bind(f.user).execute(&f.pool).await.unwrap();
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT user_id FROM auth_email_attachments WHERE user_id=$1 FOR UPDATE")
        .bind(f.user)
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let realm = f.realm;
    let current = f.current.verifier();
    let finish = tokio::spawn(async move {
        store
            .finish_email_attachment(
                realm,
                current,
                proof.verifier(),
                browser.verifier(),
                [8; 32],
            )
            .await
    });
    wait_for_lock(
        &f.pool,
        "SELECT user_id FROM auth_email_attachments%FOR UPDATE%",
    )
    .await;
    wait_until(
        &f.pool,
        "SELECT expires_at<=clock_timestamp() FROM auth_email_attachments WHERE user_id=$1",
        f.user,
    )
    .await;
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), finish)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.email().await, None);
}

#[sqlx::test(migrations = "./migrations")]
async fn final_audit_wait_cannot_extend_proof_expiry_or_original_passkey_freshness(pool: PgPool) {
    for expire_proof in [true, false] {
        let f = Fixture::new(pool.clone()).await;
        let (proof, browser) = f.proof("contact@example.com").await;
        if expire_proof {
            sqlx::query("UPDATE auth_email_attachments SET expires_at=clock_timestamp()+interval '5 seconds' WHERE user_id=$1")
                .bind(f.user).execute(&pool).await.unwrap();
        } else {
            sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 55 seconds' WHERE id=$1")
                .bind(f.actor).execute(&pool).await.unwrap();
        }
        let mut gate = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(5312)")
            .execute(&mut *gate)
            .await
            .unwrap();
        sqlx::raw_sql("CREATE FUNCTION gate_attachment_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='email_attached' THEN PERFORM pg_advisory_xact_lock(5312); END IF; RETURN NEW; END $$; CREATE TRIGGER gate_attachment_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION gate_attachment_audit();")
            .execute(&pool).await.unwrap();
        let store = f.store.clone();
        let realm = f.realm;
        let current = f.current.verifier();
        let finish = tokio::spawn(async move {
            store
                .finish_email_attachment(
                    realm,
                    current,
                    proof.verifier(),
                    browser.verifier(),
                    [8; 32],
                )
                .await
        });
        wait_for_lock(&pool, "%INSERT INTO auth_audit%").await;
        if expire_proof {
            wait_until(
                &pool,
                "SELECT expires_at<=clock_timestamp() FROM auth_email_attachments WHERE user_id=$1",
                f.user,
            )
            .await;
        } else {
            wait_until(&pool,"SELECT authenticated_at<=clock_timestamp()-interval '5 minutes' FROM auth_sessions WHERE id=$1",f.actor).await;
        }
        gate.commit().await.unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), finish)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::Unauthorized)
        ));
        assert_eq!(f.email().await, None);
        assert_eq!(f.audits().await, 0);
        assert!(
            f.store
                .authenticate(f.realm, f.current.verifier())
                .await
                .is_ok()
        );
        sqlx::query("DROP TRIGGER gate_attachment_audit ON auth_audit")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION gate_attachment_audit()")
            .execute(&pool)
            .await
            .unwrap();
    }
}

async fn wait_for_lock(pool: &PgPool, pattern: &str) {
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)")
                .bind(pattern).fetch_one(pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
}

async fn wait_until(pool: &PgPool, query: &str, id: Uuid) {
    assert!(
        !sqlx::query_scalar::<_, bool>(query)
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap(),
        "lock reached before deadline"
    );
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if sqlx::query_scalar::<_, bool>(query)
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}
