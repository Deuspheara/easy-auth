use crate::{deadlines::Deadline, unavailable};
use auth_core::Result;
use sqlx::PgPool;
use uuid::Uuid;

/// SMTP succeeded. Snapshot only chooses the lock owner; it never authorizes a
/// receipt. Keep owner -> claim -> notice order, matching cancellation/rotation.
pub(super) async fn delivered(pool: &PgPool, realm: Uuid, id: Uuid, lease: Uuid) -> Result<()> {
    let association: Option<(Uuid,Uuid)> = sqlx::query_as(
        "SELECT user_id,recovery_claim_id FROM auth_security_notifications WHERE realm_id=$1 AND id=$2 AND kind='passkey_recovery_started'",
    ).bind(realm).bind(id).fetch_optional(pool).await.map_err(unavailable)?;
    let Some((user, claim)) = association else {
        // Preserve ordinary notice completion, including stale/missing no-ops.
        sqlx::query(
            "DELETE FROM auth_security_notifications WHERE realm_id=$1 AND id=$2 AND lease_id=$3",
        )
        .bind(realm)
        .bind(id)
        .bind(lease)
        .execute(pool)
        .await
        .map_err(unavailable)?;
        return Ok(());
    };
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
            .bind(realm)
            .bind(user)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
    if owner.is_none() {
        // Account deletion cascades this owned queue work and cannot be reversed by an ack.
        return Ok(());
    }
    let expiry: Option<i64> = sqlx::query_scalar(r#"
        SELECT (extract(epoch FROM c.expires_at)*1000000)::bigint
        FROM auth_passkey_recovery_claims c
        JOIN auth_passkey_recovery_codes k ON k.realm_id=c.realm_id AND k.user_id=c.user_id AND k.rp_id=c.rp_id
        WHERE c.realm_id=$1 AND c.user_id=$2 AND c.id=$3 AND c.cancelled_at IS NULL
          AND c.code_version=k.version AND k.consumed_at IS NOT NULL FOR UPDATE OF c
    "#).bind(realm).bind(user).bind(claim).fetch_optional(&mut *tx).await.map_err(unavailable)?;
    let lease_until: Option<i64> = sqlx::query_scalar(
        r#"
        DELETE FROM auth_security_notifications
        WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND recovery_claim_id=$4
          AND lease_id=$5 AND lease_until>clock_timestamp()
        RETURNING (extract(epoch FROM lease_until)*1000000)::bigint
    "#,
    )
    .bind(realm)
    .bind(id)
    .bind(user)
    .bind(claim)
    .bind(lease)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    if let Some(lease_until) = lease_until {
        if let Some(expiry) = expiry {
            let live: bool = sqlx::query_scalar(
                "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1",
            )
            .bind(expiry)
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
            if live {
                // Time is observed after notice deletion waits. The first accepted
                // receipt fixes the delay; duplicate/stale workers cannot restart it.
                sqlx::query(
                    r#"
                    WITH instant AS (SELECT clock_timestamp() AS now)
                    UPDATE auth_passkey_recovery_claims c
                    SET notified_at=now,not_before=now+make_interval(secs=>c.delay_seconds)
                    FROM instant WHERE c.realm_id=$1 AND c.user_id=$2 AND c.id=$3
                      AND c.notification_required AND c.notified_at IS NULL
                      AND c.cancelled_at IS NULL AND c.expires_at>now
                "#,
                )
                .bind(realm)
                .bind(user)
                .bind(claim)
                .execute(&mut *tx)
                .await
                .map_err(unavailable)?;
                Deadline::proof(expiry).check(&mut tx).await?;
            }
        }
        Deadline::proof(lease_until).check(&mut tx).await?;
    }
    tx.commit().await.map_err(unavailable)
}
