use super::keeping;
use crate::support::{realm, signed_in};
use auth_core::{Error, Repository, RetentionCategory, RetentionRepository, run_retention};
use sqlx::PgPool;
use uuid::Uuid;

async fn expired_challenges(pool: &PgPool, realm: Uuid, count: i32) {
    sqlx::query("INSERT INTO auth_email_challenges(realm_id,token_hash,browser_hash,email,expires_at) SELECT $1,sha256(convert_to(gen_random_uuid()::text,'UTF8')),decode(repeat('01',32),'hex'),'owned-expired@example.test',statement_timestamp()-interval '1 second' FROM generate_series(1,$2)")
        .bind(realm).bind(count).execute(pool).await.unwrap();
}

async fn challenges(pool: &PgPool, realm: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM auth_email_challenges WHERE realm_id=$1")
        .bind(realm)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn finite_pass_exercises_every_category_and_preserves_live_and_foreign_authority(
    pool: PgPool,
) {
    let (store, a) = realm(pool.clone()).await;
    let b = Uuid::new_v4();
    store.ensure_realm(b).await.unwrap();
    let first = signed_in(&store, a, "owned-first@example.test").await;
    let second = signed_in(&store, b, "owned-second@example.test").await;
    expired_challenges(&pool, a, 1).await;
    expired_challenges(&pool, b, 1).await;
    let report = run_retention(&store, a, keeping()).await.unwrap();
    assert_eq!(report.steps.len(), 28);
    assert_eq!(
        report
            .steps
            .iter()
            .map(|step| step.effects.deleted)
            .sum::<u64>(),
        1
    );
    assert_eq!(challenges(&pool, a).await, 0);
    assert_eq!(challenges(&pool, b).await, 1);
    assert!(store.authenticate(a, first.verifier()).await.is_ok());
    assert!(store.authenticate(b, second.verifier()).await.is_ok());
    assert!(matches!(
        store.authenticate(b, first.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert!(
        run_retention(&store, a, keeping())
            .await
            .unwrap()
            .steps
            .iter()
            .all(|step| step.effects.deleted == 0)
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn batches_skip_locked_rows_and_never_exceed_the_fixed_limit(pool: PgPool) {
    let (store, a) = realm(pool.clone()).await;
    expired_challenges(&pool, a, 130).await;
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT token_hash FROM auth_email_challenges WHERE realm_id=$1 ORDER BY token_hash LIMIT 1 FOR UPDATE")
        .bind(a).fetch_all(&mut *gate).await.unwrap();
    let first = store
        .retain_batch(a, RetentionCategory::EmailChallenges, keeping())
        .await
        .unwrap();
    assert_eq!(first.deleted, 64);
    let (left, right) = tokio::join!(
        store.retain_batch(a, RetentionCategory::EmailChallenges, keeping()),
        store.retain_batch(a, RetentionCategory::EmailChallenges, keeping())
    );
    let (left, right) = (left.unwrap(), right.unwrap());
    assert!(left.deleted <= 64 && right.deleted <= 64);
    assert_eq!(left.deleted + right.deleted, 65);
    assert_eq!(challenges(&pool, a).await, 1);
    gate.commit().await.unwrap();
    assert_eq!(
        store
            .retain_batch(a, RetentionCategory::EmailChallenges, keeping())
            .await
            .unwrap()
            .deleted,
        1
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn live_proofs_remain_usable_and_nil_realm_cannot_mutate_anything(pool: PgPool) {
    let (store, a) = realm(pool.clone()).await;
    let (proof, browser) = crate::support::challenge(&store, a, "owned-live@example.test").await;
    expired_challenges(&pool, a, 1).await;
    assert!(matches!(
        store
            .retain_batch(Uuid::nil(), RetentionCategory::EmailChallenges, keeping())
            .await,
        Err(Error::InvalidInput)
    ));
    assert_eq!(challenges(&pool, a).await, 2);
    assert_eq!(
        store
            .retain_batch(a, RetentionCategory::EmailChallenges, keeping())
            .await
            .unwrap()
            .deleted,
        1
    );
    let session = auth_core::Secret::generate().unwrap();
    store
        .finish_email(a, proof.verifier(), browser.verifier(), session.verifier())
        .await
        .unwrap();
    assert!(store.authenticate(a, session.verifier()).await.is_ok());
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_category_rolls_back_its_batch_but_does_not_claim_earlier_commits_were_undone(
    pool: PgPool,
) {
    let (store, a) = realm(pool.clone()).await;
    expired_challenges(&pool, a, 1).await;
    let token = auth_core::Secret::generate().unwrap();
    let browser = auth_core::Secret::generate().unwrap();
    store
        .begin_password_reset(
            a,
            "owned-failure@example.test",
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    sqlx::query("UPDATE auth_password_resets SET expires_at=statement_timestamp()-interval '1 second' WHERE realm_id=$1")
        .bind(a).execute(&pool).await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION owned_retention_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned retention fault'; END $$; CREATE TRIGGER owned_retention_fault BEFORE DELETE ON auth_password_resets FOR EACH ROW EXECUTE FUNCTION owned_retention_fault()")
        .execute(&pool).await.unwrap();
    assert!(matches!(
        run_retention(&store, a, keeping()).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        challenges(&pool, a).await,
        0,
        "the earlier successful category really committed"
    );
    let resets: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_password_resets WHERE realm_id=$1")
            .bind(a)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(resets, 1, "failed batch must not partly delete its state");
    sqlx::raw_sql("DROP TRIGGER owned_retention_fault ON auth_password_resets; DROP FUNCTION owned_retention_fault()")
        .execute(&pool).await.unwrap();
    let report = run_retention(&store, a, keeping()).await.unwrap();
    assert_eq!(
        report
            .steps
            .iter()
            .find(|step| step.category == RetentionCategory::PasswordResets)
            .unwrap()
            .effects
            .deleted,
        1
    );
}
