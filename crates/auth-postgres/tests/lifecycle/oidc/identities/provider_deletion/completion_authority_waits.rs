use super::super::setup::wait_for_lock;
use super::completion_setup::{account, fresh, proof, snapshot};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn final_deletion_rechecks_all_original_caps_after_unchanged_configuration_and_owner_waits(
    pool: PgPool,
) {
    for lock in ["configuration", "owner"] {
        for cap_kind in ["proof", "session", "authentication"] {
            let (f, user, current) = account(pool.clone()).await;
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
            let mut gate = f.pool.begin().await.unwrap();
            let pattern = if lock == "configuration" {
                let c = f.policy.configuration();
                sqlx::query("SELECT id FROM auth_oauth_connections WHERE realm_id=$1 AND id=$2 AND client_id=$3 FOR UPDATE")
                    .bind(c.realm()).bind(c.connection()).bind(c.client()).execute(&mut *gate).await.unwrap();
                "%FROM auth_oauth_connections WHERE%FOR SHARE%"
            } else {
                sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
                    .bind(f.realm())
                    .bind(user.id)
                    .execute(&mut *gate)
                    .await
                    .unwrap();
                "%authentication_policy='provider_required'%FOR UPDATE%"
            };
            let store = f.store.clone();
            let action =
                tokio::spawn(async move { OidcAccountDeletion::new(store).finish(deletion).await });
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
                "test infrastructure: observed {lock}/{cap_kind} wait must precede expiry"
            );
            f.wait_for_expiry(cap).await;
            gate.commit().await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), action)
                .await
                .expect("test infrastructure: original-authority waiter must finish")
                .unwrap();
            assert!(
                matches!(result, Err(Error::Unauthorized)),
                "SQL/pool failures do not prove an expiry rejection"
            );
            assert!(
                snapshot(&f).await == before,
                "failed original authority cannot delete/touch account or restore consumed OAuth state"
            );
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
