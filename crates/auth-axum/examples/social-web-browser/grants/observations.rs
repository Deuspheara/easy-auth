use super::*;
use serde::Serialize;
use std::sync::atomic::Ordering;

#[derive(Serialize, sqlx::FromRow)]
pub(in super::super) struct Snapshot {
    active: i64,
    pending: i64,
    leased: i64,
    failed: i64,
    completed: i64,
    expired: i64,
    encrypted: i64,
    attempts: i64,
    #[sqlx(skip)]
    calls: usize,
}
impl Fixture {
    pub async fn snapshot(&self) -> FixtureResult<Snapshot> {
        // Finite aggregate observations only: never return raw records, binding
        // IDs, provider subject, ciphertext, secret, OAuth state or proof to the parent.
        let mut snapshot: Snapshot = sqlx::query_as(
            r#"
            SELECT count(*) FILTER (WHERE state='active') AS active,
                count(*) FILTER (WHERE state='pending') AS pending,
                count(*) FILTER (WHERE state='leased') AS leased,
                count(*) FILTER (WHERE state='failed') AS failed,
                count(*) FILTER (WHERE state='completed') AS completed,
                count(*) FILTER (WHERE state='expired') AS expired,
                count(*) FILTER (WHERE ciphertext IS NOT NULL OR key_id IS NOT NULL) AS encrypted,
                coalesce(sum(attempts),0)::bigint AS attempts
            FROM auth_apple_grants WHERE realm_id=$1
            "#,
        )
        .bind(self.realm)
        .fetch_one(&self.pool)
        .await?;
        snapshot.calls = self.http.calls.load(Ordering::SeqCst);
        Ok(snapshot)
    }
}
