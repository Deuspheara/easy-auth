//! Trusted timestamp fixture only. No HTTP bypass, receipt fabrication, key or
//! session mutation. Original expiry and production delay policy are unchanged.
use sqlx::PgPool;
use std::io::BufRead;
use uuid::Uuid;

pub(super) fn listen(pool: PgPool, realm: Uuid, rp: String) {
    let runtime = tokio::runtime::Handle::current();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().take(128) {
            let Ok(line) = line else { break };
            if line == "observe-owned-notices" {
                let drained = runtime
                    .block_on(async {
                        sqlx::query_scalar::<_, i64>(
                            "SELECT count(*) FROM auth_security_notifications WHERE realm_id=$1",
                        )
                        .bind(realm)
                        .fetch_one(&pool)
                        .await
                    })
                    .is_ok_and(|count| count == 0);
                println!(
                    "{}",
                    serde_json::json!({"recovery_notices_drained":drained})
                );
                continue;
            }
            let owner = if line.len() <= 80 {
                line.strip_prefix("mature-owned-claim ")
                    .and_then(|value| Uuid::parse_str(value).ok())
            } else {
                None
            };
            let prepared = match owner {
                Some(owner) => runtime.block_on(mature(&pool, realm, owner, &rp)).is_ok(),
                None => false,
            };
            println!(
                "{}",
                serde_json::json!({"recovery_clock_prepared":prepared})
            );
        }
    });
}

async fn mature(pool: &PgPool, realm: Uuid, owner: Uuid, rp: &str) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query_scalar::<_,Uuid>("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 AND authentication_policy='passkey_required' FOR UPDATE")
        .bind(realm).bind(owner).fetch_one(&mut *tx).await?;
    // Require a genuinely reserved current generation and, for contact owners,
    // the real worker's first accepted receipt before arranging elapsed time.
    let id:Uuid=sqlx::query_scalar(r#"
        SELECT c.id FROM auth_passkey_recovery_claims c
        JOIN auth_passkey_recovery_codes k ON k.realm_id=c.realm_id AND k.user_id=c.user_id AND k.rp_id=c.rp_id
        WHERE c.realm_id=$1 AND c.user_id=$2 AND c.rp_id=$3 AND c.code_version=k.version
          AND k.consumed_at IS NOT NULL AND c.cancelled_at IS NULL AND c.completed_at IS NULL
          AND c.expires_at>clock_timestamp() AND c.delay_seconds=$4
          AND (NOT c.notification_required OR c.notified_at IS NOT NULL)
        FOR UPDATE OF c
    "#).bind(realm).bind(owner).bind(rp).bind(auth_core::PASSKEY_RECOVERY_DELAY_SECONDS).fetch_one(&mut *tx).await?;
    sqlx::query(r#"
        WITH instant AS (SELECT clock_timestamp()-make_interval(secs=>$4::integer+60) AS before_delay)
        UPDATE auth_passkey_recovery_claims SET created_at=before_delay,
          notified_at=CASE WHEN notification_required THEN before_delay ELSE NULL END,
          not_before=before_delay+make_interval(secs=>delay_seconds)
        FROM instant WHERE realm_id=$1 AND user_id=$2 AND id=$3
    "#).bind(realm).bind(owner).bind(id).bind(auth_core::PASSKEY_RECOVERY_DELAY_SECONDS).execute(&mut *tx).await?;
    tx.commit().await
}
