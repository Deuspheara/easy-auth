use super::super::deletion_setup::Fixture;
use crate::support::observation;
use auth_core::Error;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn original_parent_session_cap_is_not_extended_by_other_session_activity(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let expiry:i64=sqlx::query_scalar("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE realm_id=$1 AND token_hash=$2 RETURNING (extract(epoch FROM expires_at)*1000000)::bigint")
        .bind(f.user.realm_id).bind(f.current.verifier().as_slice()).fetch_one(&f.source.pool).await.unwrap();
    let start = f.requests.start(&f.current).await.unwrap();
    let original:i64=sqlx::query_scalar("SELECT (extract(epoch FROM expires_at)*1000000)::bigint FROM auth_saml_requests WHERE request_id=$1")
        .bind(start.request_id()).fetch_one(&f.source.pool).await.unwrap();
    assert_eq!(original, expiry);
    sqlx::query("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '1 hour',last_seen_at=clock_timestamp() WHERE realm_id=$1 AND token_hash=$2")
        .bind(f.user.realm_id).bind(f.current.verifier().as_slice()).execute(&f.source.pool).await.unwrap();
    let observer = observation::observer(&f.source.pool).await;
    observation::expired(&observer, original).await;
    assert!(matches!(
        f.requests
            .prepare_response(
                &f.current,
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn owner_policy_is_rechecked_after_an_observed_start_wait(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let observer = observation::observer(&f.source.pool).await;
    let mut gate = f.source.pool.begin().await.unwrap();
    sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2")
        .bind(f.user.realm_id).bind(f.user.id).execute(&mut *gate).await.unwrap();
    let pending = tokio::spawn(async move { f.requests.start(&f.current).await });
    observation::locked(
        &observer,
        "%SELECT id,email,display_name,authentication_policy FROM auth_users%FOR UPDATE%",
    )
    .await;
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn expiry_during_observed_delete_write_rolls_back_consumption(pool: PgPool) {
    let f = Arc::new(Fixture::new(pool).await);
    let start = f.requests.start(&f.current).await.unwrap();
    let cap: i64 = sqlx::query_scalar("UPDATE auth_saml_requests SET expires_at=clock_timestamp()+interval '4 seconds' WHERE request_id=$1 RETURNING (extract(epoch FROM expires_at)*1000000)::bigint")
        .bind(start.request_id()).fetch_one(&f.source.pool).await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION hold_deletion_take() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(5701); RETURN OLD; END $$; CREATE TRIGGER hold_deletion_take BEFORE DELETE ON auth_saml_requests FOR EACH ROW EXECUTE FUNCTION hold_deletion_take();")
        .execute(&f.source.pool).await.unwrap();
    let observer = observation::observer(&f.source.pool).await;
    let mut gate = f.source.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5701)")
        .execute(&mut *gate)
        .await
        .unwrap();
    let actor = f.clone();
    let completion = tokio::spawn(async move {
        actor
            .requests
            .prepare_response(
                &actor.current,
                start.request_id(),
                start.relay_state(),
                start.browser_proof(),
            )
            .await
    });
    observation::locked(
        &observer,
        "%DELETE FROM auth_saml_requests%purpose='delete_account'%",
    )
    .await;
    let live: bool =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1")
            .bind(cap)
            .fetch_one(&observer)
            .await
            .unwrap();
    assert!(live, "the observed storage wait must precede expiry");
    observation::expired(&observer, cap).await;
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), completion)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.pending().await,
        1,
        "failed final check rolls back the DELETE"
    );
    assert_eq!(super::super::setup::facts(&f.source).await, (1, 1, 1, 2, 1));
    sqlx::raw_sql("DROP TRIGGER hold_deletion_take ON auth_saml_requests; DROP FUNCTION hold_deletion_take();").execute(&f.source.pool).await.unwrap();
    let healthy = f.requests.start(&f.current).await.unwrap();
    assert_eq!(
        f.pending().await,
        1,
        "healthy admission prunes expired state"
    );
    f.requests
        .cancel(
            &f.current,
            healthy.request_id(),
            healthy.relay_state(),
            healthy.browser_proof(),
        )
        .await
        .unwrap();
    assert_eq!(f.pending().await, 0);
}
