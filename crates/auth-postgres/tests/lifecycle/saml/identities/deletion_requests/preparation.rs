use super::super::deletion_setup::Fixture;
use auth_core::{Error, Repository};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn forced_request_is_bound_one_use_and_preserves_original_cap_without_authority(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let start = f.requests.start(&f.current).await.unwrap();
    let url = url::Url::parse(start.authorization_url()).unwrap();
    let encoded = url
        .query_pairs()
        .find(|(name, _)| name == "SAMLRequest")
        .unwrap()
        .1
        .into_owned();
    let xml = String::from_utf8(
        saml_rs::binding::deflate_raw_decode(&saml_rs::binding::base64_decode(&encoded).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(xml.contains("ForceAuthn=\"true\""));
    let (purpose,user,session,identity,cap):(String,uuid::Uuid,uuid::Uuid,uuid::Uuid,i64)=sqlx::query_as("SELECT purpose,user_id,session_id,identity_id,(extract(epoch FROM expires_at)*1000000)::bigint FROM auth_saml_requests WHERE request_id=$1")
        .bind(start.request_id()).fetch_one(&f.source.pool).await.unwrap();
    assert_eq!(purpose, "delete_account");
    assert_eq!(user, f.user.id);
    let prepared = f
        .requests
        .prepare_response(
            &f.current,
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    assert_eq!(prepared.binding().user, user);
    assert_eq!(prepared.binding().session, session);
    assert_eq!(prepared.binding().identity, identity);
    assert_eq!(prepared.expires_at_us(), cap);
    assert!(format!("{prepared:?}").contains("REDACTED"));
    assert_eq!(f.pending().await, 0);
    assert!(matches!(
        f.requests
            .prepare_response(
                &f.current,
                start.request_id(),
                start.relay_state(),
                start.browser_proof()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(super::super::setup::facts(&f.source).await, (1, 1, 1, 2, 1));
    f.source
        .store
        .authenticate(f.user.realm_id, f.current.verifier())
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn old_or_unknown_authentication_can_request_reauthentication_but_not_erase(pool: PgPool) {
    let f = Fixture::new(pool).await;
    for instant in ["'-infinity'", "clock_timestamp()-interval '1 hour'"] {
        sqlx::query(&format!("UPDATE auth_sessions SET authenticated_at={instant} WHERE realm_id=$1 AND token_hash=$2"))
            .bind(f.user.realm_id).bind(f.current.verifier().as_slice()).execute(&f.source.pool).await.unwrap();
        let start = f.requests.start(&f.current).await.unwrap();
        f.requests
            .cancel(
                &f.current,
                start.request_id(),
                start.relay_state(),
                start.browser_proof(),
            )
            .await
            .unwrap();
    }
    assert_eq!(super::super::setup::facts(&f.source).await, (1, 1, 1, 2, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn insertion_failure_rolls_back_pending_state_and_never_masks_storage_as_denial(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    sqlx::raw_sql("CREATE FUNCTION reject_deletion_start() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned fixture storage failure'; END $$; CREATE TRIGGER reject_deletion_start BEFORE INSERT ON auth_saml_requests FOR EACH ROW EXECUTE FUNCTION reject_deletion_start();")
        .execute(&f.source.pool).await.unwrap();
    assert!(matches!(
        f.requests.start(&f.current).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(f.pending().await, 0);
    sqlx::raw_sql("DROP TRIGGER reject_deletion_start ON auth_saml_requests; DROP FUNCTION reject_deletion_start();").execute(&f.source.pool).await.unwrap();
    let start = f.requests.start(&f.current).await.unwrap();
    f.requests
        .cancel(
            &f.current,
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
}
