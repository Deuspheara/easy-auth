//! One fixed trusted-storage fixture, not an HTTP endpoint or authentication bypass.
//! Chrome creates credentials with counter 1, even when assertions are later configured
//! counterless. Seed the last fixture account's unused credential as a counterless
//! record before testing genuine browser-signed zero assertions against stored zero.
use sqlx::PgPool;
use std::io::BufRead;
use uuid::Uuid;

pub(super) fn listen(pool: PgPool, realm: Uuid, owner: Uuid) {
    let runtime = tokio::runtime::Handle::current();
    std::thread::spawn(move || {
        let Some(Ok(command)) = std::io::stdin().lock().lines().next() else {
            return;
        };
        if command != "prepare-counterless-fixture" {
            return;
        }
        let prepared = runtime.block_on(prepare(&pool, realm, owner)).is_ok();
        println!(
            "{}",
            serde_json::json!({"counterless_fixture_prepared":prepared})
        );
    });
}

async fn prepare(pool: &PgPool, realm: Uuid, owner: Uuid) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(realm)
        .bind(owner)
        .fetch_one(&mut *tx)
        .await?;
    let updated = sqlx::query(r#"
        UPDATE auth_passkeys SET credential=convert_to(
            jsonb_set(convert_from(credential,'UTF8')::jsonb,'{cred,counter}','0'::jsonb)::text,'UTF8')
        WHERE realm_id=$1 AND user_id=$2 AND last_used_at IS NULL
          AND convert_from(credential,'UTF8')::jsonb #>> '{cred,counter}'='1'
    "#).bind(realm).bind(owner).execute(&mut *tx).await?;
    if updated.rows_affected() != 1 {
        return Err(sqlx::Error::RowNotFound);
    }
    // The preceding signed-zero rejection leaves its retryable challenge alive.
    // Cancel it as fixture setup before preparing the independent stored-zero state.
    sqlx::query("DELETE FROM auth_passkey_authentications WHERE realm_id=$1 AND user_id=$2")
        .bind(realm)
        .bind(owner)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}
