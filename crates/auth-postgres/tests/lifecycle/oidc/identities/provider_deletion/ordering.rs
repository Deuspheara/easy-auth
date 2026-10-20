use super::super::setup::{Fixture, wait_for_lock};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn provider_disable_winning_configuration_lock_rejects_deletion_start_and_consumed_exchange(
    pool: PgPool,
) {
    for check_exchange in [false, true] {
        let f = Fixture::new(pool.clone(), OidcJitPolicy::Allow).await;
        let (user, current) = f
            .sign_in
            .finish(f.mapped("owned", json!({})).await)
            .await
            .unwrap();
        let c = f.policy.configuration().clone();
        let browser = Secret::generate().unwrap();
        let purpose = OAuthPurpose::DeleteProviderAccount {
            user: user.id,
            session: current.verifier(),
        };
        let flow = OAuthTransactions::new(c.clone(), f.store.clone());
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-delete-ordering",
            purpose: purpose.clone(),
        };
        let exchange = if check_exchange {
            let start = flow.begin(&intent).await.unwrap();
            Some(
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
                .unwrap(),
            )
        } else {
            None
        };
        let before = f.facts().await;
        let mut gate = f.pool.begin().await.unwrap();
        sqlx::query("UPDATE auth_oauth_connections SET enabled=false,revision=$4 WHERE realm_id=$1 AND id=$2 AND client_id=$3")
            .bind(c.realm()).bind(c.connection()).bind(c.client()).bind(Uuid::new_v4()).execute(&mut *gate).await.unwrap();
        let store = f.store.clone();
        let action = tokio::spawn(async move {
            if let Some(exchange) = exchange {
                store.check_oidc_exchange(&exchange).await.map(|_| ())
            } else {
                flow.begin(&OAuthIntent {
                    browser: &browser,
                    source: "owned-delete-ordering",
                    purpose,
                })
                .await
                .map(|_| ())
            }
        });
        wait_for_lock(&f.pool, "%FROM auth_oauth_connections WHERE%FOR SHARE%").await;
        gate.commit().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), action)
            .await
            .expect("test infrastructure: disabled-source waiter must finish")
            .unwrap();
        assert!(matches!(result, Err(Error::Unauthorized)));
        assert_eq!(f.facts().await, before);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn provider_account_policy_is_rechecked_after_owner_wait_during_deletion_start_and_consume(
    pool: PgPool,
) {
    for consume in [false, true] {
        let f = Fixture::new(pool.clone(), OidcJitPolicy::Allow).await;
        let (user, current) = f
            .sign_in
            .finish(f.mapped("owned", json!({})).await)
            .await
            .unwrap();
        let c = f.policy.configuration().clone();
        let browser = Secret::generate().unwrap();
        let purpose = OAuthPurpose::DeleteProviderAccount {
            user: user.id,
            session: current.verifier(),
        };
        let flow = OAuthTransactions::new(c.clone(), f.store.clone());
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-delete-policy",
            purpose: purpose.clone(),
        };
        let pending = if consume {
            Some(flow.begin(&intent).await.unwrap())
        } else {
            None
        };
        let before = f.facts().await;
        let cap = pending.as_ref().map(|pending| pending.expires_us);
        let mut gate = f.pool.begin().await.unwrap();
        sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2")
            .bind(f.realm()).bind(user.id).execute(&mut *gate).await.unwrap();
        let action = tokio::spawn(async move {
            let intent = OAuthIntent {
                browser: &browser,
                source: "owned-delete-policy",
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
        wait_for_lock(
            &f.pool,
            "%authentication_policy='provider_required'%FOR UPDATE%",
        )
        .await;
        gate.commit().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), action)
            .await
            .expect("test infrastructure: policy waiter must finish")
            .unwrap();
        assert!(matches!(result, Err(Error::Unauthorized)));
        if let Some(cap) = cap {
            let live: bool = sqlx::query_scalar(
                "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1",
            )
            .bind(cap)
            .fetch_one(&f.pool)
            .await
            .expect("test infrastructure: policy denial must precede original expiry");
            assert!(live, "proof expiry must not masquerade as policy denial");
        }
        assert_eq!(
            f.facts().await,
            before,
            "failed reauthorization cannot consume pending state"
        );
    }
}
