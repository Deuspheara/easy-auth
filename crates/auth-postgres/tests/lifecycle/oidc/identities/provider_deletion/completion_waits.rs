use super::super::setup::wait_for_lock;
use super::completion_setup::{account, fresh, proof, remove_tail_gate, snapshot, tail_gate};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn final_deletion_audit_and_notice_waits_preserve_proof_session_and_signed_freshness_caps(
    pool: PgPool,
) {
    for table in ["auth_audit", "auth_security_notifications"] {
        for cap_kind in ["proof", "session", "authentication"] {
            let (f, user, current) = account(pool.clone()).await;
            if table == "auth_security_notifications" {
                sqlx::query("UPDATE auth_users SET email='tail-control@example.test',email_verified_at=clock_timestamp() WHERE realm_id=$1 AND id=$2")
                    .bind(f.realm()).bind(user.id).execute(&f.pool).await.unwrap();
            }
            let authenticated = f.now_seconds().await
                - if cap_kind == "authentication" {
                    i64::try_from(MAX_OIDC_DELETION_AUTH_AGE_SECONDS).unwrap() - 4
                } else {
                    0
                };
            let deletion = proof(
                &f,
                &user,
                &current,
                json!({"auth_time":authenticated}),
                if cap_kind == "proof" { Some(2) } else { None },
            )
            .await;
            let cap = match cap_kind {
                "proof" => deletion.identity().expires_us(),
                "session" => sqlx::query_scalar("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE realm_id=$1 AND token_hash=$2 RETURNING (extract(epoch FROM expires_at)*1000000)::bigint")
                    .bind(f.realm()).bind(current.verifier().as_slice()).fetch_one(&f.pool).await.unwrap(),
                _ => (authenticated+i64::try_from(MAX_OIDC_DELETION_AUTH_AGE_SECONDS).unwrap())*1_000_000,
            };
            let before = snapshot(&f).await;
            // An audit table lock would stop prior deidentification, not the
            // final insertion. Gate exactly the intended destructive tail.
            let gate = tail_gate(&f, table, "account_deleted").await;
            let store = f.store.clone();
            let action =
                tokio::spawn(async move { OidcAccountDeletion::new(store).finish(deletion).await });
            let pattern = if table == "auth_audit" {
                "%INSERT INTO auth_audit%"
            } else {
                "%INSERT INTO auth_security_notifications%"
            };
            wait_for_lock(&f.pool, pattern).await;
            let live: bool = sqlx::query_scalar(
                "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1",
            )
            .bind(cap)
            .fetch_one(&f.pool)
            .await
            .unwrap();
            assert!(
                live,
                "test infrastructure: {table}/{cap_kind} tail wait must precede original expiry"
            );
            f.wait_for_expiry(cap).await;
            gate.commit().await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), action)
                .await
                .expect("test infrastructure: released deletion tail must finish")
                .unwrap();
            assert!(
                matches!(result, Err(Error::Unauthorized)),
                "infrastructure failure cannot prove expired deletion authority"
            );
            assert!(
                snapshot(&f).await == before,
                "expired tail restores exact account/session/audit/notice/pending/cooldown state"
            );
            remove_tail_gate(&f, table).await;
            // Use a genuinely new login/flow, never revive an expired original
            // session or replay a consumed provider proof for the valid control.
            let (_, valid) = f
                .sign_in
                .finish(f.mapped("owned", json!({})).await)
                .await
                .unwrap();
            OidcAccountDeletion::new(f.store.clone())
                .finish(fresh(&f, &user, &valid).await)
                .await
                .unwrap();
        }
    }
}
