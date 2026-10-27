use super::super::setup::Fixture;
use super::*;
use sqlx::PgPool;
#[sqlx::test(migrations = "./migrations")]
async fn ledger_constraints_reject_source_retargeting_and_unprotected_or_ambiguous_states(
    pool: PgPool,
) {
    let f = Fixture::new(pool, AppleClientType::Web, OidcJitPolicy::Allow).await;
    sign_in(&f, "constraints").await;
    for (assignment, code) in [
        ("ciphertext=NULL", "23514"),
        ("identity_id=NULL", "23514"),
        ("key_id=NULL", "23514"),
        ("state='pending'", "23514"),
        ("attempts=9", "23514"),
        ("ciphertext='raw credential with spaces'", "23514"),
        ("client_id='00000000-0000-0000-0000-000000000001'", "23503"),
    ] {
        let error = sqlx::query(&format!(
            "UPDATE auth_apple_grants SET {assignment} WHERE realm_id=$1"
        ))
        .bind(f.realm())
        .execute(&f.pool)
        .await
        .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some(code)
        );
    }
    assert_eq!(envelopes(&f).await.len(), 1);
}
