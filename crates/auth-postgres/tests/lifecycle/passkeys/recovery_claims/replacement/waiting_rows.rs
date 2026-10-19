use super::*;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn unchanged_candidate_lock_wait_rechecks_original_registration_and_assertion_expiry(
    pool: PgPool,
) {
    for mode in ["registration", "assertion"] {
        let mut f = Replacement::new(pool.clone(), true).await;
        f.mature().await;
        let (id, registration) = f.registration().await;
        let proof = if mode == "assertion" {
            let pending = f
                .flow
                .finish_registration(f.target, id, &f.c.browser, SOURCE, &registration)
                .await
                .unwrap();
            let signed = f
                .token
                .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
                .unwrap();
            Some(f.proof(id, &signed).await)
        } else {
            None
        };
        sqlx::query("UPDATE auth_passkey_recovery_replacements SET expires_at=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1").bind(f.c.f.realm).execute(&pool).await.unwrap();
        let before = f.c.snapshot().await;
        let mut gate = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT id FROM auth_passkey_recovery_replacements WHERE realm_id=$1 FOR UPDATE",
        )
        .bind(f.c.f.realm)
        .execute(&mut *gate)
        .await
        .unwrap();
        let request = f.request(id);
        let action = async {
            if let Some(proof) = proof {
                f.c.f
                    .store
                    .commit_recovery_replacement(&request, proof, [94; 32])
                    .await
            } else {
                f.flow
                    .finish_registration(f.target, id, &f.c.browser, SOURCE, &registration)
                    .await
                    .map(|_| ())
            }
        };
        let release = async {
            let observer = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_with(pool.connect_options().as_ref().clone())
                .await
                .expect("test infrastructure: candidate lock observer");
            tokio::time::timeout(Duration::from_secs(5),async {
                loop {
                    let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id FROM auth_passkey_recovery_replacements%FOR UPDATE%')").fetch_one(&observer).await.unwrap();
                    if waiting {break;}
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.expect("test infrastructure: operation must wait on unchanged candidate");
            assert!(sqlx::query_scalar::<_,bool>("SELECT expires_at>clock_timestamp() FROM auth_passkey_recovery_replacements WHERE realm_id=$1").bind(f.c.f.realm).fetch_one(&observer).await.unwrap(),"test infrastructure: row wait precedes expiry");
            tokio::time::timeout(Duration::from_secs(8),async {
                while !sqlx::query_scalar::<_,bool>("SELECT expires_at<=clock_timestamp() FROM auth_passkey_recovery_replacements WHERE realm_id=$1").bind(f.c.f.realm).fetch_one(&observer).await.unwrap() {tokio::time::sleep(Duration::from_millis(20)).await;}
            }).await.expect("test infrastructure: candidate deadline crossing");
            gate.commit().await.unwrap();
            observer.close().await;
        };
        let (result, ()) = tokio::join!(action, release);
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "infrastructure errors never prove expired proof rejection"
        );
        f.c.unchanged(before).await;
    }
}
