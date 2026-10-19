use super::authorization;
use crate::unavailable;
use auth_core::{MAX_PASSKEYS_PER_ACCOUNT, PasskeyInfo, PasskeyManagementRequest, Result};
use sqlx::{PgPool, Row};

pub(super) async fn list(
    pool: &PgPool,
    request: &PasskeyManagementRequest,
) -> Result<Vec<PasskeyInfo>> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let caller = authorization::caller(&mut tx, request).await?;
    let rows = sqlx::query(
        r#"
            SELECT id,management_version,label,
                (extract(epoch FROM created_at)*1000)::bigint AS created_at_ms,
                (extract(epoch FROM last_used_at)*1000)::bigint AS last_used_at_ms
            FROM auth_passkeys WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3
            ORDER BY id LIMIT $4
            "#,
    )
    .bind(request.realm)
    .bind(caller.user)
    .bind(&request.rp_id)
    .bind(MAX_PASSKEYS_PER_ACCOUNT as i64)
    .fetch_all(&mut *tx)
    .await
    .map_err(unavailable)?;
    let keys = rows
        .into_iter()
        .map(|row| PasskeyInfo {
            id: row.get("id"),
            version: row.get("management_version"),
            label: row.get("label"),
            created_at_ms: row.get("created_at_ms"),
            last_used_at_ms: row.get("last_used_at_ms"),
        })
        .collect();
    caller.deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(keys)
}
