use super::setup::Fixture;
use auth_core::{Error, MAX_SAML_PENDING_PER_CONNECTION};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn expired_operations_cannot_cancel_and_are_pruned_on_next_admission(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let old = f.flow.start().await.unwrap();
    sqlx::query("UPDATE auth_saml_requests SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '5 minutes'")
        .execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.flow
            .cancel(old.request_id(), old.relay_state(), old.browser_proof())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 1);
    let fresh = f.flow.start().await.unwrap();
    assert_eq!(f.pending().await, 1);
    f.flow
        .cancel(
            fresh.request_id(),
            fresh.relay_state(),
            fresh.browser_proof(),
        )
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn pending_storage_quota_rejects_without_creating_authority_or_extra_state(pool: PgPool) {
    let f = Fixture::new(pool).await;
    // A finite database fixture at the declared storage boundary. No request
    // flood, signature work, stress measurement or resource-exhaustion probe.
    sqlx::query(r#"
        INSERT INTO auth_saml_requests(realm_id,connection_id,client_id,revision,request_id,relay_hash,browser_hash,expires_at)
        SELECT $1,$2,$3,$4,'_fixture_'||i,decode(lpad(to_hex(i),64,'0'),'hex'),decode(repeat('01',32),'hex'),clock_timestamp()+interval '5 minutes'
        FROM generate_series(1,$5::integer) AS i
    "#).bind(f.registration.realm()).bind(f.registration.connection()).bind(f.registration.client())
        .bind(f.registration.revision()).bind(MAX_SAML_PENDING_PER_CONNECTION as i32)
        .execute(&f.pool).await.unwrap();
    assert!(matches!(f.flow.start().await, Err(Error::RateLimited)));
    assert_eq!(f.pending().await, MAX_SAML_PENDING_PER_CONNECTION);
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_users")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(users, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_insert_returns_unavailable_and_leaves_no_pending_request(pool: PgPool) {
    let f = Fixture::new(pool).await;
    sqlx::raw_sql("CREATE FUNCTION reject_saml_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned storage fault'; END $$; CREATE TRIGGER reject_saml_insert BEFORE INSERT ON auth_saml_requests FOR EACH ROW EXECUTE FUNCTION reject_saml_insert()")
        .execute(&f.pool).await.unwrap();
    assert!(matches!(f.flow.start().await, Err(Error::Unavailable)));
    assert_eq!(f.pending().await, 0);
    sqlx::query("DROP TRIGGER reject_saml_insert ON auth_saml_requests")
        .execute(&f.pool)
        .await
        .unwrap();
    f.flow.start().await.unwrap();
    assert_eq!(f.pending().await, 1);
}
