use super::super::setup::Fixture;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn deletion_reauthentication_rechecks_revocation_idle_absolute_and_account_policy(
    pool: PgPool,
) {
    for mutation in [
        "UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1",
        "UPDATE auth_sessions SET last_seen_at=clock_timestamp()-interval '31 minutes' WHERE realm_id=$1",
        "UPDATE auth_sessions SET expires_at=clock_timestamp() WHERE realm_id=$1",
        "UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1",
    ] {
        let f = Fixture::new(pool.clone(), OidcJitPolicy::Allow).await;
        let (user, current) = f
            .sign_in
            .finish(f.mapped("owned", json!({})).await)
            .await
            .unwrap();
        let c = f.policy.configuration();
        let flow = OAuthTransactions::new(c.clone(), f.store.clone());
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-delete-invalidation",
            purpose: OAuthPurpose::DeleteProviderAccount {
                user: user.id,
                session: current.verifier(),
            },
        };
        let start = flow.begin(&intent).await.unwrap();
        sqlx::query(mutation)
            .bind(f.realm())
            .execute(&f.pool)
            .await
            .unwrap();
        let before = f.facts().await;
        assert!(matches!(
            flow.begin(&intent).await,
            Err(Error::Unauthorized)
        ));
        let result = flow
            .consume(
                &intent,
                &start.state,
                start.proof,
                OAuthCallback {
                    redirect: c.redirect(),
                    issuer: Some(c.issuer()),
                },
            )
            .await;
        assert!(matches!(result, Err(Error::Unauthorized)));
        assert_eq!(
            f.facts().await,
            before,
            "rejection must neither consume proof nor change account/session/audit"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn consumed_deletion_exchange_rechecks_current_source_and_original_session_before_provider_io(
    pool: PgPool,
) {
    for disable in [false, true] {
        let mut f = Fixture::new(pool.clone(), OidcJitPolicy::Allow).await;
        let (user, current) = f
            .sign_in
            .finish(f.mapped("owned", json!({})).await)
            .await
            .unwrap();
        let c = f.policy.configuration();
        let flow = OAuthTransactions::new(c.clone(), f.store.clone());
        let browser = Secret::generate().unwrap();
        let purpose = OAuthPurpose::DeleteProviderAccount {
            user: user.id,
            session: current.verifier(),
        };
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-delete-exchange",
            purpose: purpose.clone(),
        };
        let start = flow.begin(&intent).await.unwrap();
        let exchange = flow
            .consume(
                &intent,
                &start.state,
                start.proof,
                OAuthCallback {
                    redirect: c.redirect(),
                    issuer: Some(c.issuer()),
                },
            )
            .await
            .unwrap();
        f.store.check_oidc_exchange(&exchange).await.unwrap();
        if disable {
            f.store
                .disable_oauth_connection(c.realm(), c.connection(), c.client())
                .await
                .unwrap();
        } else {
            sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND token_hash=$2")
                .bind(f.realm()).bind(current.verifier().as_slice()).execute(&f.pool).await.unwrap();
        }
        let before = f.facts().await;
        assert!(matches!(
            f.store.check_oidc_exchange(&exchange).await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(f.facts().await, before);
        if disable {
            f.reconfigure(OidcJitPolicy::Allow).await;
            f.store
                .enable_oauth_connection(f.policy.configuration())
                .await
                .unwrap();
            assert!(
                matches!(
                    f.store.check_oidc_exchange(&exchange).await,
                    Err(Error::Unauthorized)
                ),
                "re-enable cannot restore a consumed old-revision proof"
            );
        }
        let (_, new_session) = f
            .sign_in
            .finish(f.mapped("owned", json!({})).await)
            .await
            .unwrap();
        let flow = OAuthTransactions::new(f.policy.configuration().clone(), f.store.clone());
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-delete-new-flow",
            purpose: OAuthPurpose::DeleteProviderAccount {
                user: user.id,
                session: new_session.verifier(),
            },
        };
        let start = flow.begin(&intent).await.unwrap();
        flow.cancel(&intent, &start.state, &start.proof)
            .await
            .unwrap();
    }
}
