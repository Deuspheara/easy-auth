use super::*;
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn audit_and_notice_failure_roll_back_rename_and_removal(pool: PgPool) {
    for remove in [false, true] {
        for notice in [false, true] {
            let f = Management::new(pool.clone(), false).await;
            let (id, mut token) = f.add_key("Spare").await;
            f.sign_in(&mut token).await;
            let key = f.key(id).await;
            let before = f.snapshot().await;
            let table = if notice {
                "auth_security_notifications"
            } else {
                "auth_audit"
            };
            sqlx::query(&format!("ALTER TABLE {table} ADD CONSTRAINT reject_management CHECK(kind NOT IN ('passkey_renamed','passkey_removed','passkeys_changed')) NOT VALID"))
                .execute(&pool).await.unwrap();
            let result = if remove {
                f.flow.remove(&f.session, SOURCE, key.id, key.version).await
            } else {
                f.flow
                    .rename(&f.session, SOURCE, key.id, key.version, "New label")
                    .await
                    .map(|_| ())
            };
            assert!(
                matches!(result, Err(Error::Unavailable)),
                "injected persistence failure must not become authorization success"
            );
            f.assert_unchanged(before).await;
            sqlx::query(&format!(
                "ALTER TABLE {table} DROP CONSTRAINT reject_management"
            ))
            .execute(&pool)
            .await
            .unwrap();
            if remove {
                f.flow
                    .remove(&f.session, SOURCE, key.id, key.version)
                    .await
                    .unwrap();
            } else {
                f.flow
                    .rename(&f.session, SOURCE, key.id, key.version, "Retry succeeds")
                    .await
                    .unwrap();
            }
        }
    }
}
