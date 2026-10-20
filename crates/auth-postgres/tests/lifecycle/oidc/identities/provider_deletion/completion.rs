use super::super::setup::Fixture;
use super::completion_setup::{account, fresh, proof};
use crate::support::signed_in;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn fresh_exact_provider_proof_deletes_email_free_owner_and_cascades_authority_without_fabricating_notice(
    pool: PgPool,
) {
    let (f, user, current) = account(pool).await;
    let (_, other_current) = f
        .sign_in
        .finish(f.mapped("owned", json!({})).await)
        .await
        .unwrap();
    let c = f.policy.configuration();
    let foreign = Fixture::scoped(
        f.pool.clone(),
        f.store.clone(),
        Uuid::new_v4(),
        c.connection(),
        c.client(),
        OidcJitPolicy::Allow,
    )
    .await;
    let (foreign_user, foreign_session) = foreign
        .sign_in
        .finish(foreign.mapped("owned", json!({})).await)
        .await
        .unwrap();
    let mailbox = signed_in(&f.store, f.realm(), "untouched@example.test").await;
    let browser = Secret::generate().unwrap();
    let flow = OAuthTransactions::new(c.clone(), f.store.clone());
    let intent = OAuthIntent {
        browser: &browser,
        source: "owned-delete-pending",
        purpose: OAuthPurpose::DeleteProviderAccount {
            user: user.id,
            session: current.verifier(),
        },
    };
    let pending = flow.begin(&intent).await.unwrap();
    let previous_audits: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM auth_audit WHERE realm_id=$1 AND user_id=$2")
            .bind(f.realm())
            .bind(user.id)
            .fetch_all(&f.pool)
            .await
            .unwrap();
    assert_eq!(previous_audits.len(), 2);
    let old_signin = f.mapped("owned", json!({})).await;
    let old_cap = old_signin.identity().expires_us();
    let deletion = fresh(&f, &user, &current).await;
    OidcAccountDeletion::new(f.store.clone())
        .finish(deletion)
        .await
        .unwrap();
    let remains: (i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1 AND id=$2),(SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1 AND user_id=$2),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1 AND user_id=$2),(SELECT count(*) FROM auth_oauth_transactions WHERE realm_id=$1 AND user_id=$2)")
        .bind(f.realm()).bind(user.id).fetch_one(&f.pool).await.unwrap();
    assert_eq!(remains, (0, 0, 0, 0));
    let erased: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE id=ANY($1) AND subject_erased AND user_id IS NULL AND actor_session_id IS NULL AND session_id IS NULL AND passkey_id IS NULL AND recovery_claim_id IS NULL")
        .bind(&previous_audits).fetch_one(&f.pool).await.unwrap();
    assert_eq!(erased, 2);
    let deleted: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='account_deleted' AND user_id IS NULL AND subject_erased")
        .bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(deleted, 1);
    let notices: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_security_notifications")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        notices, 0,
        "no fabricated contact or notice for an email-free account"
    );
    for session in [&current, &other_current] {
        assert!(matches!(
            f.store.authenticate(f.realm(), session.verifier()).await,
            Err(Error::Unauthorized)
        ));
    }
    assert!(matches!(
        flow.cancel(&intent, &pending.state, &pending.proof).await,
        Err(Error::Unauthorized)
    ));
    let live: bool =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1")
            .bind(old_cap)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(
        live,
        "test infrastructure: old proof must still be within its original cap"
    );
    assert!(matches!(
        f.sign_in.finish(old_signin).await,
        Err(Error::Unauthorized)
    ));
    assert!(
        matches!(
            f.sign_in.finish(f.mapped("owned", json!({})).await).await,
            Err(Error::Unauthorized)
        ),
        "fresh anonymous JIT must respect deletion cooldown"
    );
    let blocked: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_oidc_deleted_subjects WHERE realm_id=$1 AND blocked_until>clock_timestamp()")
        .bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(blocked, 1);
    assert_eq!(
        foreign
            .store
            .authenticate(foreign.realm(), foreign_session.verifier())
            .await
            .unwrap(),
        foreign_user
    );
    f.store
        .authenticate(f.realm(), mailbox.verifier())
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn provider_deletion_uses_only_stored_verified_contact_and_keeps_mailbox_fallback_denied(
    pool: PgPool,
) {
    let (f, user, current) = account(pool).await;
    // Trusted owned persistence fixture, not a provider-email attachment API.
    sqlx::query("UPDATE auth_users SET email='stored-contact@example.test',email_verified_at=clock_timestamp() WHERE realm_id=$1 AND id=$2")
        .bind(f.realm()).bind(user.id).execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.store
            .begin_account_deletion(
                f.realm(),
                current.verifier(),
                Secret::generate().unwrap().verifier(),
                Secret::generate().unwrap().verifier()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let deletion = proof(&f, &user, &current, json!({"auth_time":f.now_seconds().await,"email":"provider-attribute@example.test","email_verified":true}), None).await;
    OidcAccountDeletion::new(f.store.clone())
        .finish(deletion)
        .await
        .unwrap();
    let notice = f
        .store
        .claim_security_notice(f.realm())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(notice.recipient, "stored-contact@example.test");
    assert!(matches!(notice.kind, SecurityNoticeKind::AccountDeleted));
    let row: (Option<Uuid>, String) = sqlx::query_as(
        "SELECT user_id,recipient FROM auth_security_notifications WHERE realm_id=$1",
    )
    .bind(f.realm())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(row.0.is_none());
    assert_eq!(row.1, "stored-contact@example.test");
}

#[sqlx::test(migrations = "./migrations")]
async fn deletion_needs_neither_jit_allow_nor_optional_profile_for_an_existing_provider_owner(
    pool: PgPool,
) {
    let (mut f, user, _) = account(pool).await;
    f.reconfigure(OidcJitPolicy::Deny).await;
    let (_, current) = f
        .sign_in
        .finish(f.mapped("owned", json!({"name":null})).await)
        .await
        .unwrap();
    let deletion = proof(
        &f,
        &user,
        &current,
        json!({"auth_time":f.now_seconds().await,"name":null}),
        None,
    )
    .await;
    assert!(deletion.display_name().is_none());
    f.store
        .finish_oidc_account_deletion(deletion)
        .await
        .unwrap();
    assert!(matches!(
        f.store.authenticate(f.realm(), current.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 3, 0));
}
