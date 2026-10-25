mod atomicity;
mod lifecycle;
mod worker;
use super::setup::*;
use std::sync::Arc;
use std::sync::atomic::Ordering;

fn vault() -> Arc<AppleGrantVault> {
    Arc::new(
        AppleGrantVault::new(
            AppleGrantKey::new(Uuid::new_v4(), vec![29; 32]).unwrap(),
            vec![],
        )
        .unwrap(),
    )
}
async fn captured(pool: PgPool, vault: Arc<AppleGrantVault>) -> Fixture {
    super::composition::with_grants(pool, Some(vault)).await
}
async fn grants(f: &Fixture) -> Vec<(String, i32, bool)> {
    sqlx::query_as("SELECT state,attempts,ciphertext IS NULL AND key_id IS NULL FROM auth_apple_grants WHERE realm_id=$1 ORDER BY id")
        .bind(f.auth.realm()).fetch_all(&f.pool).await.unwrap()
}
async fn unlink(f: &Fixture, owner: Uuid, session: &str) -> Response {
    let page = f.inventory(session).await;
    let identity = &page["providers"][0]["id"];
    f.post(
        "/v1/account/providers/oidc/unlink",
        json!({"expected_owner":owner,"identity":identity,"confirmation":"unlink this account"}),
        session,
    )
    .await
}
