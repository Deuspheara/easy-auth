use super::keeping;
use crate::support::realm;
use auth_core::{RetentionCategory, RetentionRepository};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn admission_keeps_previous_current_and_future_windows_in_all_namespaces(pool: PgPool) {
    let (store, a) = realm(pool.clone()).await;
    let b = uuid::Uuid::new_v4();
    store.ensure_realm(b).await.unwrap();
    let cases = [
        (
            RetentionCategory::RateBuckets,
            "auth_rate_buckets",
            "dimension,key_hash,",
            "'source',decode(repeat('01',32),'hex'),",
            600,
        ),
        (
            RetentionCategory::OAuthAdmission,
            "auth_oauth_admission",
            "dimension,key_hash,",
            "'start_source',decode(repeat('01',32),'hex'),",
            600,
        ),
        (
            RetentionCategory::IssuerAdmission,
            "auth_issuer_token_admission",
            "source_hash,",
            "decode(repeat('01',32),'hex'),",
            60,
        ),
    ];
    for (category, table, columns, values, period) in cases {
        let insert = format!(
            "INSERT INTO {table}(realm_id,{columns}window_id,attempts) SELECT $1,{values}floor(extract(epoch FROM statement_timestamp())/{period})::bigint+delta,1 FROM generate_series(-2,1) AS windows(delta)"
        );
        sqlx::query(&insert).bind(a).execute(&pool).await.unwrap();
        sqlx::query(&insert).bind(b).execute(&pool).await.unwrap();
        assert_eq!(
            store
                .retain_batch(a, category, keeping())
                .await
                .unwrap()
                .deleted,
            1
        );
        let count = format!("SELECT count(*) FROM {table} WHERE realm_id=$1");
        let kept: i64 = sqlx::query_scalar(&count)
            .bind(a)
            .fetch_one(&pool)
            .await
            .unwrap();
        let foreign: i64 = sqlx::query_scalar(&count)
            .bind(b)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!((kept, foreign), (3, 4));
    }
}
