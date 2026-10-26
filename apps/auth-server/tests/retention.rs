//! Actual one-shot executable against owned SQLx PostgreSQL databases.
use auth_core::{Repository, Secret};
use auth_postgres::Postgres;
use sqlx::{ConnectOptions, PgPool, migrate::Migrator};
use std::{borrow::Cow, process::Command};
use uuid::Uuid;

fn command(pool: &PgPool, realm: Uuid) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_easy-auth"));
    command
        .env_clear()
        .arg("retention")
        .env(
            "DATABASE_URL",
            pool.connect_options().to_url_lossy().as_str(),
        )
        .env("AUTH_REALM_ID", realm.to_string())
        .env("AUTH_RETENTION_AUDIT", "keep")
        .env("AUTH_RETENTION_NOTICES", "keep")
        .env("AUTH_DATABASE_MIGRATIONS", "run")
        .env("AUTH_PUBLIC_URL", "private-marker")
        .env("SMTP_PASSWORD", "private-marker")
        .env("AUTH_OIDC_ISSUER", "private-marker");
    command
}

async fn proof(store: &Postgres, realm: Uuid, address: &str) {
    store.ensure_realm(realm).await.unwrap();
    store
        .begin_email(
            realm,
            address,
            Secret::generate().unwrap().verifier(),
            Secret::generate().unwrap().verifier(),
            [1; 32],
        )
        .await
        .unwrap();
}

async fn count(pool: &PgPool, realm: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM auth_email_challenges WHERE realm_id=$1")
        .bind(realm)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn command_prunes_only_selected_realm_without_starting_or_requiring_server_services(
    pool: PgPool,
) {
    let store = Postgres::new(pool.clone());
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    proof(&store, a, "owned-command@example.test").await;
    proof(&store, b, "owned-command@example.test").await;
    sqlx::query(
        "UPDATE auth_email_challenges SET expires_at=statement_timestamp()-interval '1 second'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let output = command(&pool, a).output().unwrap();
    assert!(output.status.success(), "one-shot retention failed");
    assert!(output.stderr.is_empty());
    let report = String::from_utf8(output.stdout).unwrap();
    assert_eq!(report.lines().count(), 28);
    assert!(
        report.contains("EmailChallenges: deleted=1 expired_ciphertexts=0 exhausted_leases=0\n")
    );
    assert_eq!((count(&pool, a).await, count(&pool, b).await), (0, 1));
    let rerun = command(&pool, a).output().unwrap();
    assert!(rerun.status.success());
    assert!(rerun.stderr.is_empty());
    assert!(
        String::from_utf8(rerun.stdout)
            .unwrap()
            .contains("EmailChallenges: deleted=0 expired_ciphertexts=0 exhausted_leases=0\n")
    );
}

#[sqlx::test(migrations = false)]
async fn command_refuses_old_schema_without_migration_or_cleanup_fallback(pool: PgPool) {
    let migrations = sqlx::migrate!("../../crates/auth-postgres/migrations")
        .iter()
        .filter(|migration| migration.version <= 38)
        .cloned()
        .collect();
    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
    .run(&pool)
    .await
    .unwrap();
    let store = Postgres::new(pool.clone());
    let realm = Uuid::new_v4();
    proof(&store, realm, "owned-old-schema@example.test").await;
    sqlx::query(
        "UPDATE auth_email_challenges SET expires_at=statement_timestamp()-interval '1 second'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let output = command(&pool, realm).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"Error: \"database retention failed; earlier batches may have committed\"\n"
    );
    assert_eq!(count(&pool, realm).await, 1);
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 38);
    let migrated: bool =
        sqlx::query_scalar("SELECT to_regclass('auth_retention_audit_age') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!migrated);
}
