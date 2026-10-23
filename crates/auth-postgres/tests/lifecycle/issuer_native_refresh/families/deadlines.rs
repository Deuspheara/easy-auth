use super::*;
use crate::support::lock_observation::{locked, observer};
use auth_core::IssuerTokenError;

#[sqlx::test]
async fn final_audit_wait_cannot_revive_the_pre_rotation_family_idle_deadline(pool: PgPool) {
    let f = std::sync::Arc::new(Fixture::new(pool).await);
    let code = f.code().await;
    let issued = f.exchange(&code).await.unwrap();
    let cap:i64=sqlx::query_scalar("UPDATE auth_issuer_native_families SET idle_until_us=(extract(epoch FROM clock_timestamp())*1000000)::bigint+3000000 RETURNING idle_until_us").fetch_one(&f.base.pool).await.unwrap();
    let mut gate = f.base.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5481)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION native_rotation_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='issuer_native_rotated' THEN PERFORM pg_advisory_xact_lock(5481); END IF; RETURN NEW; END $$; CREATE TRIGGER native_rotation_gate BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION native_rotation_gate();").execute(&f.base.pool).await.unwrap();
    let view = observer(&f.base.pool).await;
    let worker = f.clone();
    let token = issued.refresh_token().into();
    let task = tokio::spawn(async move {
        worker
            .refresher()
            .refresh(&worker.authentication(), &token, "127.0.0.1")
            .await
    });
    locked(&view, "%INSERT INTO auth_audit%").await;
    let now: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&view)
            .await
            .unwrap();
    assert!(
        now < cap,
        "must observe the write wait inside the original native idle cap"
    );
    tokio::time::sleep(std::time::Duration::from_micros(
        (cap - now) as u64 + 50_000,
    ))
    .await;
    gate.commit().await.unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert_eq!(f.facts().await, (1, 1, 1, 1, 1));
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT generation=0 AND idle_until_us=$1 FROM auth_issuer_native_families"
        )
        .bind(cap)
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT spent_at_us IS NULL FROM auth_issuer_native_refresh_tokens"
        )
        .fetch_one(&f.base.pool)
        .await
        .unwrap()
    );
}
