use super::setup::{Fixture, counts, expiring_proof, proof};
use crate::support::observation;
use auth_core::{Error, Repository, SamlAccountDeletion};
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn original_cap_expiring_after_user_erasure_during_final_audit_wait_rolls_back_every_write(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let input = expiring_proof(&f).await;
    let cap = input.assertion().expires_at_us();
    sqlx::raw_sql("CREATE FUNCTION hold_saml_erasure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(5702); RETURN NEW; END $$; CREATE TRIGGER hold_saml_erasure BEFORE INSERT ON auth_audit FOR EACH ROW WHEN (NEW.kind='account_deleted') EXECUTE FUNCTION hold_saml_erasure();")
        .execute(&f.source.pool).await.unwrap();
    let observer = observation::observer(&f.source.pool).await;
    let mut gate = f.source.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5702)")
        .execute(&mut *gate)
        .await
        .unwrap();
    let service = SamlAccountDeletion::new(f.source.store.clone());
    let deletion = tokio::spawn(async move { service.finish(input).await });
    observation::audit(&observer).await;
    assert_before_cap(&observer, cap).await;
    observation::expired(&observer, cap).await;
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), deletion)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(counts(&f).await, (1, 1, 1, 2, 1, 0));
    let cooldowns: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_saml_deleted_subjects")
        .fetch_one(&f.source.pool)
        .await
        .unwrap();
    assert_eq!(cooldowns, 0);
    f.source
        .store
        .authenticate(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
    sqlx::raw_sql(
        "DROP TRIGGER hold_saml_erasure ON auth_audit; DROP FUNCTION hold_saml_erasure();",
    )
    .execute(&f.source.pool)
    .await
    .unwrap();
    SamlAccountDeletion::new(f.source.store.clone())
        .finish(proof(&f, "normal").await)
        .await
        .unwrap();
    assert_eq!(counts(&f).await, (0, 0, 0, 4, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn unchanged_owner_wait_cannot_outlive_original_initiating_session_or_keep_replay_reservations(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    sqlx::query("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '4 seconds' WHERE realm_id=$1 AND token_hash=$2")
        .bind(f.user.realm_id).bind(f.current.verifier().as_slice()).execute(&f.source.pool).await.unwrap();
    let input = proof(&f, "normal").await;
    let cap = input.assertion().expires_at_us();
    let observer = observation::observer(&f.source.pool).await;
    let mut gate = f.source.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(f.user.realm_id)
        .bind(f.user.id)
        .fetch_one(&mut *gate)
        .await
        .unwrap();
    let service = SamlAccountDeletion::new(f.source.store.clone());
    let deletion = tokio::spawn(async move { service.finish(input).await });
    observation::locked(
        &observer,
        "%SELECT id,email,display_name,authentication_policy FROM auth_users%FOR UPDATE%",
    )
    .await;
    assert_before_cap(&observer, cap).await;
    observation::expired(&observer, cap).await;
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), deletion)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(counts(&f).await, (1, 1, 1, 2, 1, 0));
}

async fn assert_before_cap(pool: &PgPool, cap: i64) {
    let live: bool =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1")
            .bind(cap)
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(
        live,
        "test infrastructure: observed wait must precede the retained cap"
    );
}
