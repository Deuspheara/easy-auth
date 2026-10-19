use super::*;
use auth_core::Error;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn expiry_during_the_final_audit_write_rolls_back_user_key_session_and_fact(pool: PgPool) {
    let mut f = Signup::new(pool).await;
    let (id, response) = f.assertion().await;
    sqlx::query("UPDATE auth_passkey_signups SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1")
        .bind(id).execute(&f.pool).await.unwrap();
    let proof = f.proof(id, &response).await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(53010)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION gate_signup_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='passkey_signed_up' THEN PERFORM pg_advisory_xact_lock(53010); END IF; RETURN NEW; END $$; CREATE TRIGGER gate_signup_audit BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION gate_signup_audit();")
        .execute(&f.pool).await.unwrap();
    let request = f.request(id);
    let store = f.store.clone();
    let finish = tokio::spawn(async move { store.commit_signup(&request, proof, [1; 32]).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=53010 AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT granted)")
                .fetch_one(&f.pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    let live: bool = sqlx::query_scalar(
        "SELECT expires_at>clock_timestamp() FROM auth_passkey_signups WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(live);
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let expired: bool = sqlx::query_scalar(
                "SELECT expires_at<=clock_timestamp() FROM auth_passkey_signups WHERE id=$1",
            )
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
            if expired {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), finish)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_cannot_advance_after_expiry_during_an_unchanged_row_wait(pool: PgPool) {
    let mut f = Signup::new(pool).await;
    let (id, response) = f.registration().await;
    sqlx::query("UPDATE auth_passkey_signups SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1")
        .bind(id).execute(&f.pool).await.unwrap();
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_passkey_signups WHERE id=$1 FOR UPDATE")
        .bind(id)
        .execute(&mut *gate)
        .await
        .unwrap();
    let flow = f.flow;
    let browser = f.browser;
    let finish = tokio::spawn(async move {
        flow.finish_registration(&browser, SOURCE, id, &response)
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id FROM auth_passkey_signups%FOR UPDATE%')")
                .fetch_one(&f.pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    let live: bool = sqlx::query_scalar(
        "SELECT expires_at>clock_timestamp() FROM auth_passkey_signups WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(live);
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let expired: bool = sqlx::query_scalar(
                "SELECT expires_at<=clock_timestamp() FROM auth_passkey_signups WHERE id=$1",
            )
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
            if expired {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), finish)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    let stage: String = sqlx::query_scalar("SELECT stage FROM auth_passkey_signups WHERE id=$1")
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(stage, "registration");
}

#[sqlx::test(migrations = "./migrations")]
async fn signup_expiry_after_a_rolled_back_key_uniqueness_wait_rolls_back_new_identity(
    pool: PgPool,
) {
    let mut f = Signup::new(pool).await;
    let (id, response) = f.assertion().await;
    sqlx::query("UPDATE auth_passkey_signups SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1")
        .bind(id).execute(&f.pool).await.unwrap();
    let proof = f.proof(id, &response).await;
    let realm = Uuid::new_v4();
    let owner = Uuid::new_v4();
    f.store.ensure_realm(realm).await.unwrap();
    sqlx::query("INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,'existing@example.com')")
        .bind(realm)
        .bind(owner)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("INSERT INTO auth_passkeys(realm_id,id,user_id,rp_id,credential_id,credential,label) VALUES ($1,$2,$3,$4,$5,$6,'Pending competitor')")
        .bind(realm).bind(Uuid::new_v4()).bind(owner).bind(proof.rp_id())
        .bind(proof.credential_id()).bind(proof.expected_credential_for_database())
        .execute(&mut *gate).await.unwrap();
    let request = f.request(id);
    let store = f.store.clone();
    let finish = tokio::spawn(async move { store.commit_signup(&request, proof, [1; 32]).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%INSERT INTO auth_passkeys%')")
                .fetch_one(&f.pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    let live: bool = sqlx::query_scalar(
        "SELECT expires_at>clock_timestamp() FROM auth_passkey_signups WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(live);
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let expired: bool = sqlx::query_scalar(
                "SELECT expires_at<=clock_timestamp() FROM auth_passkey_signups WHERE id=$1",
            )
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
            if expired {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    gate.rollback().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), finish)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn signup_expiry_is_rechecked_after_an_unchanged_pending_row_wait(pool: PgPool) {
    let mut f = Signup::new(pool).await;
    let (id, response) = f.assertion().await;
    sqlx::query("UPDATE auth_passkey_signups SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1")
        .bind(id).execute(&f.pool).await.unwrap();
    let proof = f.proof(id, &response).await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_passkey_signups WHERE id=$1 FOR UPDATE")
        .bind(id)
        .execute(&mut *gate)
        .await
        .unwrap();
    let request = f.request(id);
    let store = f.store.clone();
    let finish = tokio::spawn(async move { store.commit_signup(&request, proof, [1; 32]).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id FROM auth_passkey_signups%FOR UPDATE%')")
                .fetch_one(&f.pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    let live: bool = sqlx::query_scalar(
        "SELECT expires_at>clock_timestamp() FROM auth_passkey_signups WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(live);
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let expired: bool = sqlx::query_scalar(
                "SELECT expires_at<=clock_timestamp() FROM auth_passkey_signups WHERE id=$1",
            )
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
            if expired {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), finish)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
}
