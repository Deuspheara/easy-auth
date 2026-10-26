//! Explain the actual candidate builder, with ordinary PostgreSQL planning enabled.
use super::*;
use auth_core::RetentionHorizon;
use serde_json::Value;
use sqlx::{Execute, PgPool};

fn keeping() -> RetentionPolicy {
    RetentionPolicy::new(RetentionHorizon::keep(), RetentionHorizon::keep())
}

async fn plan(pool: &PgPool, realm: Uuid, category: RetentionCategory) -> Value {
    let enabled: String = sqlx::query_scalar("SHOW enable_seqscan")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(
        enabled, "on",
        "do not force an index to manufacture plan evidence"
    );
    let rule = rules::for_category(category, keeping()).unwrap();
    let mut builder = candidates(realm, &rule);
    let mut query = builder.build();
    let statement = format!("EXPLAIN (FORMAT JSON) {}", query.sql());
    let arguments = query.take_arguments().unwrap().unwrap();
    sqlx::query_scalar_with(&statement, arguments)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn uses_index(plan: &Value, name: &str) -> bool {
    match plan {
        Value::Object(fields) => {
            fields.get("Index Name").and_then(Value::as_str) == Some(name)
                || fields.values().any(|value| uses_index(value, name))
        }
        Value::Array(values) => values.iter().any(|value| uses_index(value, name)),
        _ => false,
    }
}

fn index_names(plan: &Value) -> Vec<&str> {
    match plan {
        Value::Object(fields) => {
            let mut names: Vec<_> = fields
                .get("Index Name")
                .and_then(Value::as_str)
                .into_iter()
                .collect();
            for value in fields.values() {
                names.extend(index_names(value));
            }
            names
        }
        Value::Array(values) => values.iter().flat_map(index_names).collect(),
        _ => Vec::new(),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn realm_expiry_index_is_selected_for_the_actual_candidate_query(pool: PgPool) {
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    for realm in [a, b] {
        crate::Postgres::new(pool.clone())
            .ensure_realm(realm)
            .await
            .unwrap();
        // A large foreign-realm backlog is exactly where the composite index
        // must avoid scanning the old global expiry index's foreign rows. With
        // only four globally expired rows that older index is a legitimate plan.
        sqlx::query("INSERT INTO auth_email_challenges(realm_id,token_hash,browser_hash,email,expires_at) SELECT $1,sha256(convert_to(gen_random_uuid()::text,'UTF8')),decode(repeat('01',32),'hex'),'owned-plan@example.test',statement_timestamp()+CASE WHEN n<=2 OR $1::uuid=$2::uuid THEN interval '-1 second' ELSE interval '1 day' END FROM generate_series(1,10000) AS records(n)")
            .bind(realm).bind(b).execute(&pool).await.unwrap();
    }
    sqlx::query("ANALYZE auth_email_challenges")
        .execute(&pool)
        .await
        .unwrap();
    let actual = plan(&pool, a, RetentionCategory::EmailChallenges).await;
    assert!(
        uses_index(&actual, "auth_retention_email_challenge"),
        "selective realm/expiry scan must use the supporting index; selected {:?}",
        index_names(&actual)
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_session_candidate_and_audit_references_use_the_new_indexes(pool: PgPool) {
    let realm = Uuid::new_v4();
    crate::Postgres::new(pool.clone())
        .ensure_realm(realm)
        .await
        .unwrap();
    let user = Uuid::new_v4();
    // Catalog/planning fixtures only; these legacy-unknown sessions are never
    // returned as credentials or accepted as genuine authentication evidence.
    sqlx::query(
        "INSERT INTO auth_users(realm_id,id,email) VALUES($1,$2,'owned-plan@example.test')",
    )
    .bind(realm)
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,expires_at) SELECT $1,gen_random_uuid(),$2,sha256(convert_to(gen_random_uuid()::text,'UTF8')),statement_timestamp()+CASE WHEN n=1 THEN interval '-1 second' ELSE interval '1 day' END FROM generate_series(1,20000) AS records(n)")
        .bind(realm).bind(user).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO auth_audit(realm_id,user_id,session_id,kind) SELECT realm_id,user_id,id,'email_authenticated' FROM auth_sessions WHERE realm_id=$1 AND expires_at>statement_timestamp()")
        .bind(realm).execute(&pool).await.unwrap();
    sqlx::query("ANALYZE auth_sessions")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ANALYZE auth_audit")
        .execute(&pool)
        .await
        .unwrap();
    let actual = plan(&pool, realm, RetentionCategory::Sessions).await;
    assert!(
        uses_index(&actual, "auth_retention_session"),
        "selective expiry scan must use its realm index"
    );
    assert!(
        uses_index(&actual, "auth_retention_audit_session"),
        "retained audit lookup must use its target index"
    );
}
