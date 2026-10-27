use super::super::setup::Fixture;
use super::*;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn captured_sign_ins_attach_every_envelope_to_actual_resolved_identity_without_plaintext(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let (user, session) = sign_in(&f, "owned-subject").await;
    let (other, _) = sign_in(&f, "owned-subject").await;
    assert_eq!(user, other);
    let envelopes = envelopes(&f).await;
    assert_eq!(envelopes.len(), 2);
    let identity: Uuid =
        sqlx::query_scalar("SELECT id FROM auth_oidc_identities WHERE realm_id=$1 AND user_id=$2")
            .bind(f.realm())
            .bind(user.id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    for envelope in envelopes {
        assert_eq!(envelope.binding().identity(), identity);
        assert_eq!(envelope.binding().realm(), f.realm());
        assert!(!envelope.ciphertext().contains("unused-owned-refresh"));
        assert!(f.vault.rewrap(&envelope).await.is_ok());
    }
    assert_eq!(
        f.store
            .authenticate(f.realm(), session.verifier())
            .await
            .unwrap(),
        user
    );
    assert_eq!(
        f.provider.posts.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn captured_link_and_local_unlink_atomically_queue_ciphertext_and_invalidate_only_removed_source(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Deny).await;
    let (owner, current) = local(&f).await;
    let linked = link(&f, &owner, &current, "linked-grant").await;
    let a = f.prepare("linked-grant", serde_json::json!({})).await;
    let (_, provider) = OidcSignIn::new(f.store.clone())
        .finish(f.policy.map(f.finish(&a).await.unwrap()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        f.store
            .authenticate(f.realm(), provider.verifier())
            .await
            .unwrap(),
        owner
    );
    let old = envelopes(&f).await.pop().unwrap();
    OidcIdentityLinking::new(f.store.clone())
        .unlink(f.realm(), &current, linked.id)
        .await
        .unwrap();
    let facts:(String,Option<Uuid>,i64)=sqlx::query_as("SELECT state,identity_id,extract(epoch FROM expires_at-queued_at)::bigint FROM auth_apple_grants WHERE realm_id=$1")
        .bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(facts, ("pending".to_owned(), None, 604800));
    let queued = envelopes(&f).await.pop().unwrap();
    assert!(queued.ciphertext() == old.ciphertext());
    assert!(f.vault.rewrap(&queued).await.is_ok());
    assert_eq!(
        f.store
            .authenticate(f.realm(), current.verifier())
            .await
            .unwrap(),
        owner
    );
    assert!(matches!(
        f.store.authenticate(f.realm(), provider.verifier()).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn ordinary_account_deletion_without_a_vault_preserves_jobs_and_erases_local_owner(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    let (user, current) = local(&f).await;
    link(&f, &user, &current, "cascade-grant").await;
    let bare = easy_auth_postgres::Postgres::new(f.pool.clone());
    let token = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    bare.begin_account_deletion(
        f.realm(),
        current.verifier(),
        token.verifier(),
        browser.verifier(),
    )
    .await
    .unwrap();
    bare.finish_account_deletion(
        f.realm(),
        current.verifier(),
        token.verifier(),
        browser.verifier(),
    )
    .await
    .unwrap();
    assert!(matches!(
        bare.authenticate(f.realm(), current.verifier()).await,
        Err(Error::Unauthorized)
    ));
    let refs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND user_id=$2")
            .bind(f.realm())
            .bind(user.id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(refs, 0);
    let (state, identity): (String, Option<Uuid>) =
        sqlx::query_as("SELECT state,identity_id FROM auth_apple_grants WHERE realm_id=$1")
            .bind(f.realm())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(state, "pending");
    assert!(identity.is_none());
    assert!(
        f.vault
            .rewrap(&envelopes(&f).await.pop().unwrap())
            .await
            .is_ok()
    );
    let forbidden:i64=sqlx::query_scalar("SELECT count(*) FROM information_schema.columns WHERE table_name='auth_apple_grants' AND column_name IN ('user_id','subject','email','token','refresh_token','access_token','client_secret')").fetch_one(&f.pool).await.unwrap();
    assert_eq!(forbidden, 0);
}
