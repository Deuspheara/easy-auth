use super::*;
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn prospective_owner_collision_never_mutates_or_logs_into_an_existing_account(pool: PgPool) {
    let mut f = Signup::new(pool).await;
    let (id, response) = f.assertion().await;
    let proof = f.proof(id, &response).await;
    sqlx::query("INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,'existing@example.com')")
        .bind(f.realm)
        .bind(proof.user_id())
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.store.commit_signup(&f.request(id), proof, [1; 32]).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.durable_counts().await, (1, 0, 0, 0));
    let email: String = sqlx::query_scalar("SELECT email FROM auth_users WHERE realm_id=$1")
        .bind(f.realm)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(email, "existing@example.com");
}

#[sqlx::test(migrations = "./migrations")]
async fn credential_owned_in_another_realm_is_never_transferred_or_merged(pool: PgPool) {
    let mut f = Signup::new(pool).await;
    let (id, response) = f.assertion().await;
    let proof = f.proof(id, &response).await;
    let foreign_realm = Uuid::new_v4();
    let foreign_owner = Uuid::new_v4();
    f.store.ensure_realm(foreign_realm).await.unwrap();
    sqlx::query("INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,'existing@example.com')")
        .bind(foreign_realm)
        .bind(foreign_owner)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO auth_passkeys(realm_id,id,user_id,rp_id,credential_id,credential,label) VALUES ($1,$2,$3,$4,$5,$6,'Existing key')")
        .bind(foreign_realm).bind(Uuid::new_v4()).bind(foreign_owner).bind(proof.rp_id())
        .bind(proof.credential_id()).bind(proof.expected_credential_for_database())
        .execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.store.commit_signup(&f.request(id), proof, [1; 32]).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
    let owner: (Uuid, Uuid) = sqlx::query_as("SELECT realm_id,user_id FROM auth_passkeys")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(owner, (foreign_realm, foreign_owner));
}
