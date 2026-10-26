use super::{apple, rules};
use crate::{Postgres, unavailable};
use async_trait::async_trait;
use auth_core::{
    Error, RETENTION_BATCH_LIMIT, Result, RetentionBatch, RetentionCategory, RetentionPolicy,
    RetentionRepository,
};
use sqlx::{Connection, QueryBuilder};
use std::time::Duration;
use uuid::Uuid;

const BATCH_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
#[path = "plan_tests.rs"]
mod plan_tests;

#[async_trait]
impl RetentionRepository for Postgres {
    async fn retain_batch(
        &self,
        realm: Uuid,
        category: RetentionCategory,
        policy: RetentionPolicy,
    ) -> Result<RetentionBatch> {
        if realm.is_nil() {
            return Err(Error::InvalidInput);
        }
        tokio::time::timeout(BATCH_TIMEOUT, run(self, realm, category, policy))
            .await
            .map_err(|_| Error::Unavailable)?
    }
}

async fn run(
    store: &Postgres,
    realm: Uuid,
    category: RetentionCategory,
    policy: RetentionPolicy,
) -> Result<RetentionBatch> {
    if category == RetentionCategory::Audit && policy.audit().seconds().is_none() {
        return Ok(RetentionBatch::default());
    }
    let mut connection = store.pool.acquire().await.map_err(unavailable)?;
    // A canceled maintenance future cannot return a transaction-bearing connection
    // to runtime. Server waits/idle lifetime also remain bounded after cancellation.
    connection.close_on_drop();
    let mut tx = Connection::begin(&mut *connection)
        .await
        .map_err(unavailable)?;
    // Embedded callers may supply a pool with a different session default. The
    // second-statement reference check requires a fresh Read Committed snapshot.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("SELECT set_config('lock_timeout','1000ms',true), set_config('statement_timeout','2000ms',true), set_config('idle_in_transaction_session_timeout','5000ms',true)")
        .execute(&mut *tx).await.map_err(unavailable)?;
    let effects = if category == RetentionCategory::AppleGrants {
        apple::retain(&mut tx, realm).await?
    } else {
        let rule = rules::for_category(category, policy).ok_or(Error::Unavailable)?;
        RetentionBatch {
            deleted: prune(&mut tx, realm, rule).await?,
            ..Default::default()
        }
    };
    tx.commit().await.map_err(unavailable)?;
    Ok(effects)
}

async fn prune(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    rule: rules::Rule,
) -> Result<u64> {
    let mut select = candidates(realm, &rule);
    let candidates: Vec<String> = select
        .build_query_scalar()
        .fetch_all(&mut **tx)
        .await
        .map_err(unavailable)?;
    if candidates.is_empty() {
        return Ok(0);
    }
    // A separate statement sees children committed while candidate locks were
    // acquired. Holding FOR UPDATE now excludes new FK references. A one-statement
    // candidate CTE would retain an older child snapshot and could cascade them.
    // Locked physical tuples cannot move/reuse their ctids until this transaction ends.
    let mut delete = QueryBuilder::new(format!("DELETE FROM {} t WHERE t.realm_id=", rule.table));
    delete
        .push_bind(realm)
        .push(" AND t.ctid=ANY(")
        .push_bind(candidates)
        .push("::text[]::tid[]) AND ");
    rule.eligibility(&mut delete);
    Ok(delete
        .build()
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?
        .rows_affected())
}

fn candidates(realm: Uuid, rule: &rules::Rule) -> QueryBuilder<'static, sqlx::Postgres> {
    let mut select = QueryBuilder::new(format!(
        "SELECT t.ctid::text FROM {} t WHERE t.realm_id=",
        rule.table
    ));
    select.push_bind(realm).push(" AND ");
    rule.eligibility(&mut select);
    select
        .push(" ORDER BY ")
        .push(rule.order)
        .push(",t.ctid FOR UPDATE OF t SKIP LOCKED LIMIT ")
        .push_bind(RETENTION_BATCH_LIMIT as i64);
    select
}
