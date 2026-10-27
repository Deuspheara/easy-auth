use super::super::setup::Fixture;
use super::*;
use sqlx::PgPool;
#[sqlx::test(migrations = "./migrations")]
async fn rotation_rewraps_active_and_pending_rows_without_changing_binding_or_queue_deadlines(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone(), AppleClientType::Web, OidcJitPolicy::Allow).await;
    let (owner, current) = local(&f).await;
    let linked = link(&f, &owner, &current, "rotated-grant").await;
    let old = envelopes(&f).await.pop().unwrap();
    let key = Uuid::new_v4();
    let vault = Arc::new(
        AppleGrantVault::new(
            AppleGrantKey::new(key, vec![31; 32]).unwrap(),
            vec![AppleGrantKey::new(old.key_id(), vec![17; 32]).unwrap()],
        )
        .unwrap(),
    );
    let rotating = easy_auth_postgres::Postgres::new(pool).with_apple_grant_vault(vault.clone());
    assert!(
        !rotating
            .rotate_apple_grant_key(Uuid::new_v4(), old.binding().grant())
            .await
            .unwrap()
    );
    assert!(
        rotating
            .rotate_apple_grant_key(f.realm(), old.binding().grant())
            .await
            .unwrap()
    );
    let active = envelopes(&f).await.pop().unwrap();
    assert!(active.binding() == old.binding());
    assert_eq!(active.key_id(), key);
    assert!(f.vault.rewrap(&active).await.is_err());
    assert!(vault.rewrap(&active).await.is_ok());
    OidcIdentityLinking::new(f.store.clone())
        .unlink(f.realm(), &current, linked.id)
        .await
        .unwrap();
    let before:(i64,i64)=sqlx::query_as("SELECT (extract(epoch FROM queued_at)*1000000)::bigint,(extract(epoch FROM expires_at)*1000000)::bigint FROM auth_apple_grants WHERE realm_id=$1").bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    assert!(
        rotating
            .rotate_apple_grant_key(f.realm(), old.binding().grant())
            .await
            .unwrap()
    );
    let after:(i64,i64)=sqlx::query_as("SELECT (extract(epoch FROM queued_at)*1000000)::bigint,(extract(epoch FROM expires_at)*1000000)::bigint FROM auth_apple_grants WHERE realm_id=$1").bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(before, after);
    assert!(envelopes(&f).await.pop().unwrap().ciphertext() != active.ciphertext());
}
