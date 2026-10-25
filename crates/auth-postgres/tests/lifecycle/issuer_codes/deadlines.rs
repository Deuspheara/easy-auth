use super::*;
use crate::support::lock_observation::{locked, observer};
use auth_core::{Error, IssuerTokenError};
use std::time::Duration;

async fn audit_gate(pool: &PgPool, kind: &str) -> sqlx::Transaction<'static, sqlx::Postgres> {
    assert!(matches!(kind, "issuer_authorized" | "issuer_code_redeemed"));
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5402)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql(&format!("CREATE FUNCTION issuer_audit_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='{kind}' THEN PERFORM pg_advisory_xact_lock(5402); END IF; RETURN NEW; END $$; CREATE TRIGGER issuer_audit_gate BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION issuer_audit_gate();"))
        .execute(pool).await.unwrap();
    gate
}
async fn expire_while_waiting(view: &PgPool, cap: i64) {
    locked(view, "%INSERT INTO auth_audit%").await;
    let live: bool =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint<$1")
            .bind(cap)
            .fetch_one(view)
            .await
            .unwrap();
    assert!(
        live,
        "the write must reach its observed gate before the original cap"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let expired: bool = sqlx::query_scalar(
                "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint>=$1",
            )
            .bind(cap)
            .fetch_one(view)
            .await
            .unwrap();
            if expired {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[sqlx::test]
async fn approval_expiring_during_final_audit_write_rolls_back_subject_code_and_audit(
    pool: PgPool,
) {
    let f = Fixture::new(&pool, false).await;
    let gate = audit_gate(&pool, "issuer_authorized").await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 58 seconds' WHERE realm_id=$1")
        .bind(f.realm).execute(&pool).await.unwrap();
    let pending = f.prepare().await.unwrap();
    let cap = pending.expires_at_us();
    let realm = f.realm;
    let view = observer(&pool).await;
    let task = tokio::spawn(async move {
        f.service
            .approve(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization(),
            )
            .await
    });
    expire_while_waiting(&view, cap).await;
    gate.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_subjects")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    let pending: bool = sqlx::query_scalar("SELECT status='pending' AND code_hash IS NULL FROM auth_issuer_authorizations WHERE realm_id=$1")
        .bind(realm).fetch_one(&pool).await.unwrap();
    assert!(pending);
    view.close().await;
}

#[sqlx::test]
async fn redemption_expiring_during_final_audit_write_rolls_back_consumption_and_scrub(
    pool: PgPool,
) {
    let f = Fixture::new(&pool, false).await;
    let pending = f.prepare().await.unwrap();
    let code = f.approve(&pending).await;
    let gate = audit_gate(&pool, "issuer_code_redeemed").await;
    let cap: i64 = sqlx::query_scalar("UPDATE auth_issuer_authorizations SET code_expires_at_us=(extract(epoch FROM clock_timestamp())*1000000)::bigint+2000000 WHERE realm_id=$1 RETURNING code_expires_at_us")
        .bind(f.realm).fetch_one(&pool).await.unwrap();
    let realm = f.realm;
    let view = observer(&pool).await;
    let task = tokio::spawn(async move {
        f.service
            .redeem(
                &f.authentication(),
                &code,
                &f.redirect,
                &f.pkce,
                "127.0.0.1",
            )
            .await
    });
    expire_while_waiting(&view, cap).await;
    gate.commit().await.unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(IssuerTokenError::InvalidGrant)
    ));
    let unchanged: bool = sqlx::query_scalar("SELECT status='approved' AND consumed_at_us IS NULL AND nonce IS NOT NULL AND state IS NOT NULL AND pkce_challenge IS NOT NULL FROM auth_issuer_authorizations WHERE realm_id=$1")
        .bind(realm).fetch_one(&pool).await.unwrap();
    assert!(unchanged);
    let redeemed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='issuer_code_redeemed'",
    )
    .bind(realm)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(redeemed, 0);
    view.close().await;
}
