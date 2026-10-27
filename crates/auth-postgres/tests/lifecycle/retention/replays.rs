use super::keeping;
use crate::support::realm;
use auth_core::{RetentionCategory, RetentionRepository};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn replay_and_deleted_subject_rows_use_their_original_final_cap_and_realm(pool: PgPool) {
    let (store, a) = realm(pool.clone()).await;
    let b = Uuid::new_v4();
    store.ensure_realm(b).await.unwrap();
    // These are storage-cap fixtures, not verified SAML messages. Genuine signed
    // deletion/cooldown cases separately run maintenance before their old checks.
    for realm in [a, b] {
        sqlx::query("INSERT INTO auth_saml_replays(realm_id,connection_id,identifier_hash,kind,retain_until) SELECT $1,$2,sha256(convert_to(gen_random_uuid()::text,'UTF8')),kind,statement_timestamp()+make_interval(secs=>seconds) FROM (VALUES ('response',-60),('assertion',-60),('response',60),('assertion',60)) AS cases(kind,seconds)")
            .bind(realm).bind(Uuid::new_v4()).execute(&pool).await.unwrap();
        for table in ["auth_oidc_deleted_subjects", "auth_saml_deleted_subjects"] {
            let insert = format!(
                "INSERT INTO {table}(realm_id,subject_hash,blocked_until) SELECT $1,sha256(convert_to(gen_random_uuid()::text,'UTF8')),statement_timestamp()+make_interval(secs=>seconds) FROM (VALUES(-60),(60)) AS cases(seconds)"
            );
            sqlx::query(&insert)
                .bind(realm)
                .execute(&pool)
                .await
                .unwrap();
        }
    }
    for (category, table, expired, remaining) in [
        (RetentionCategory::SamlReplays, "auth_saml_replays", 2, 2),
        (
            RetentionCategory::OidcCooldowns,
            "auth_oidc_deleted_subjects",
            1,
            1,
        ),
        (
            RetentionCategory::SamlCooldowns,
            "auth_saml_deleted_subjects",
            1,
            1,
        ),
    ] {
        assert_eq!(
            store
                .retain_batch(a, category, keeping())
                .await
                .unwrap()
                .deleted,
            expired
        );
        let query = format!("SELECT count(*) FROM {table} WHERE realm_id=$1");
        let selected: i64 = sqlx::query_scalar(&query)
            .bind(a)
            .fetch_one(&pool)
            .await
            .unwrap();
        let foreign: i64 = sqlx::query_scalar(&query)
            .bind(b)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!((selected, foreign), (remaining, remaining * 2));
    }
}
