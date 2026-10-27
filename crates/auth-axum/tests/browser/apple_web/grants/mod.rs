mod atomicity;
mod lifecycle;
use super::setup::*;
use sqlx::PgPool;
use uuid::Uuid;

fn vault() -> Arc<AppleGrantVault> {
    Arc::new(
        AppleGrantVault::new(
            AppleGrantKey::new(Uuid::new_v4(), vec![23; 32]).unwrap(),
            vec![],
        )
        .unwrap(),
    )
}
async fn captured(pool: PgPool) -> Fixture {
    super::composition::with_grants(pool, ORIGIN, Some(vault())).await
}
async fn grants(f: &Fixture) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM auth_apple_grants WHERE realm_id=$1")
        .bind(f.realm())
        .fetch_one(&f.pool)
        .await
        .unwrap()
}
