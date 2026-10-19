use sqlx::PgPool;

/// Historical migrations/assertions stay explicit in each scenario. Before a
/// scenario calls today's adapter, finish the later schema it requires.
pub(crate) async fn finish_upgrade_after(pool: &PgPool, version: i64) {
    for migration in sqlx::migrate!("./migrations")
        .iter()
        .filter(|migration| migration.version > version)
    {
        sqlx::raw_sql(&migration.sql)
            .execute(pool)
            .await
            .expect("test infrastructure: finish schema upgrade for current adapter");
    }
}
