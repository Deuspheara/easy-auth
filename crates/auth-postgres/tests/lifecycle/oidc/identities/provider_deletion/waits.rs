use super::super::setup::{Fixture, wait_for_lock};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn deletion_purpose_owner_pending_and_final_insert_waits_cannot_extend_original_session_cap(
    pool: PgPool,
) {
    for phase in ["owner", "insert", "consume"] {
        let f = Fixture::new(pool.clone(), OidcJitPolicy::Allow).await;
        let (user, current) = f
            .sign_in
            .finish(f.mapped("owned", json!({})).await)
            .await
            .unwrap();
        let c = f.policy.configuration().clone();
        let flow = OAuthTransactions::new(c.clone(), f.store.clone());
        let browser = Secret::generate().unwrap();
        let purpose = OAuthPurpose::DeleteProviderAccount {
            user: user.id,
            session: current.verifier(),
        };
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-delete-wait",
            purpose: purpose.clone(),
        };
        let cap: i64 = sqlx::query_scalar("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE realm_id=$1 AND token_hash=$2 RETURNING (extract(epoch FROM expires_at)*1000000)::bigint")
            .bind(f.realm()).bind(current.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
        let pending = if phase == "consume" {
            Some(flow.begin(&intent).await.unwrap())
        } else {
            None
        };
        let mut gate = f.pool.begin().await.unwrap();
        let before = f.facts().await;
        let session_rows: serde_json::Value =
            sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM auth_sessions s")
                .fetch_one(&f.pool)
                .await
                .unwrap();
        let pattern = match phase {
            "owner" => {
                sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
                    .bind(f.realm())
                    .bind(user.id)
                    .execute(&mut *gate)
                    .await
                    .unwrap();
                "%authentication_policy='provider_required'%FOR UPDATE%"
            }
            "insert" => {
                sqlx::query("SELECT pg_advisory_xact_lock(5501)")
                    .execute(&mut *gate)
                    .await
                    .unwrap();
                // A table lock would stop the preceding expired-state cleanup,
                // not the insertion whose final cap we intend to exercise.
                sqlx::raw_sql("CREATE FUNCTION deletion_insert_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(5501); RETURN NEW; END $$; CREATE TRIGGER deletion_insert_gate BEFORE INSERT ON auth_oauth_transactions FOR EACH ROW EXECUTE FUNCTION deletion_insert_gate();")
                    .execute(&f.pool).await.unwrap();
                "%INSERT INTO auth_oauth_transactions%"
            }
            _ => {
                sqlx::query("SELECT state_hash FROM auth_oauth_transactions WHERE realm_id=$1 AND state_hash=$2 FOR UPDATE")
                    .bind(f.realm()).bind(pending.as_ref().unwrap().state.verifier().as_slice()).execute(&mut *gate).await.unwrap();
                "%FROM auth_oauth_transactions%FOR UPDATE%"
            }
        };
        let action = tokio::spawn(async move {
            let intent = OAuthIntent {
                browser: &browser,
                source: "owned-delete-wait",
                purpose,
            };
            if let Some(start) = pending {
                flow.consume(
                    &intent,
                    &start.state,
                    start.proof,
                    OAuthCallback {
                        redirect: c.redirect(),
                        issuer: Some(c.issuer()),
                    },
                )
                .await
                .map(|_| ())
            } else {
                flow.begin(&intent).await.map(|_| ())
            }
        });
        wait_for_lock(&f.pool, pattern).await;
        let live: bool = sqlx::query_scalar(
            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1",
        )
        .bind(cap)
        .fetch_one(&f.pool)
        .await
        .expect("test infrastructure: observe original cap before waiting for expiry");
        assert!(
            live,
            "test infrastructure: observed {phase} lock must precede original expiry"
        );
        f.wait_for_expiry(cap).await;
        gate.commit().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), action)
            .await
            .expect("test infrastructure: released deletion-purpose waiter must finish")
            .unwrap();
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "infrastructure failure never proves deadline rejection"
        );
        if phase == "insert" {
            sqlx::raw_sql("DROP TRIGGER deletion_insert_gate ON auth_oauth_transactions; DROP FUNCTION deletion_insert_gate();")
                .execute(&f.pool).await.unwrap();
        }
        let facts = f.facts().await;
        assert_eq!(
            facts, before,
            "rejection must preserve every pre-action account/identity/session/audit/pending count"
        );
        let after: serde_json::Value =
            sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM auth_sessions s")
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert!(
            session_rows == after,
            "no session touch/revocation/mutation during rejected preparation"
        );
        assert_eq!(
            facts.4,
            if phase == "consume" { 1 } else { 0 },
            "rejected consumption rolls back expired pending state"
        );
        let (_, valid) = f
            .sign_in
            .finish(f.mapped("owned", json!({})).await)
            .await
            .unwrap();
        let flow = OAuthTransactions::new(f.policy.configuration().clone(), f.store.clone());
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-delete-valid-control",
            purpose: OAuthPurpose::DeleteProviderAccount {
                user: user.id,
                session: valid.verifier(),
            },
        };
        let start = flow.begin(&intent).await.unwrap();
        flow.cancel(&intent, &start.state, &start.proof)
            .await
            .unwrap();
    }
}
