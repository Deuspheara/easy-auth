use super::super::deletion_setup::Fixture;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn purpose_and_composite_session_identity_constraints_reject_invalid_bindings(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let start = f.requests.start(&f.current).await.unwrap();
    for mutation in [
        "purpose='sign_in'",
        "purpose='other'",
        "user_id=NULL",
        "session_id=NULL",
        "identity_id=NULL",
    ] {
        let error = sqlx::query(&format!(
            "UPDATE auth_saml_requests SET {mutation} WHERE request_id=$1"
        ))
        .bind(start.request_id())
        .execute(&f.source.pool)
        .await
        .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
    }
    for mutation in [
        "user_id=gen_random_uuid()",
        "session_id=gen_random_uuid()",
        "identity_id=gen_random_uuid()",
        "revision=gen_random_uuid()",
    ] {
        let error = sqlx::query(&format!(
            "UPDATE auth_saml_requests SET {mutation} WHERE request_id=$1"
        ))
        .bind(start.request_id())
        .execute(&f.source.pool)
        .await
        .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23503")
        );
    }
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
