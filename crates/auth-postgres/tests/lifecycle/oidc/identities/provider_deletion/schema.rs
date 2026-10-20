use super::super::setup::Fixture;
use auth_core::{OAuthIntent, OAuthPurpose, OAuthTransactions, OidcJitPolicy, Repository, Secret};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn provider_deletion_purpose_requires_both_owner_and_initiating_session(pool: PgPool) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (user, current) = f
        .sign_in
        .finish(f.mapped("owned", json!({})).await)
        .await
        .unwrap();
    let session: Uuid =
        sqlx::query_scalar("SELECT id FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
            .bind(f.realm())
            .bind(current.verifier().as_slice())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let c = f.policy.configuration();
    for (owner, session, valid) in [
        (Some(user.id), Some(session), true),
        (None, Some(session), false),
        (Some(user.id), None, false),
        (None, None, false),
    ] {
        let state = Secret::generate().unwrap().verifier();
        let result = sqlx::query("INSERT INTO auth_oauth_transactions(realm_id,connection_id,client_id,revision,state_hash,browser_hash,nonce_hash,pkce_hash,purpose,user_id,session_id,expires_at) VALUES($1,$2,$3,$4,$5,$5,$5,$5,'delete_provider_account',$6,$7,clock_timestamp()+interval '1 minute')")
            .bind(f.realm()).bind(c.connection()).bind(c.client()).bind(c.revision())
            .bind(state.as_slice()).bind(owner).bind(session).execute(&f.pool).await;
        if valid {
            assert!(
                result.is_ok(),
                "the explicit deletion purpose must support an exactly owned session"
            );
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                error
                    .as_database_error()
                    .and_then(|error| error.code())
                    .as_deref(),
                Some("23514"),
                "only the actual binding constraint proves rejection, not infrastructure failure"
            );
        }
    }
    assert_eq!(
        f.facts().await,
        (1, 1, 1, 1, 1),
        "schema admission alone grants no deletion"
    );
}

#[sqlx::test(migrations = false)]
async fn deletion_purpose_upgrade_preserves_existing_sessions_and_pending_signin_without_granting_deletion(
    pool: PgPool,
) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|migration| migration.version <= 18)
    {
        sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
    }
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
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
        source: "owned-purpose-upgrade",
        purpose: OAuthPurpose::SignIn,
    };
    let start = flow.begin(&intent).await.unwrap();
    let before = f.facts().await;
    let snapshot: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(t) FROM auth_oauth_transactions t WHERE realm_id=$1 AND state_hash=$2",
    )
    .bind(f.realm())
    .bind(start.state.verifier().as_slice())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../../migrations/0019_provider_deletion_purpose.sql"
    ))
    .execute(&f.pool)
    .await
    .unwrap();
    let after: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(t) FROM auth_oauth_transactions t WHERE realm_id=$1 AND state_hash=$2",
    )
    .bind(f.realm())
    .bind(start.state.verifier().as_slice())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(
        snapshot == after,
        "migration must retain exact original proof hashes, purpose, binding and cap"
    );
    assert_eq!(before, f.facts().await);
    assert_eq!(
        f.store
            .authenticate(f.realm(), current.verifier())
            .await
            .unwrap(),
        user
    );
    flow.cancel(&intent, &start.state, &start.proof)
        .await
        .unwrap();
    let deletion = OAuthIntent {
        browser: &browser,
        source: "owned-purpose-upgrade",
        purpose: OAuthPurpose::DeleteProviderAccount {
            user: user.id,
            session: current.verifier(),
        },
    };
    let pending = flow.begin(&deletion).await.unwrap();
    flow.cancel(&deletion, &pending.state, &pending.proof)
        .await
        .unwrap();
    assert_eq!(
        f.facts().await,
        (1, 1, 1, 1, 0),
        "purpose admission never deletes or authenticates"
    );
}
