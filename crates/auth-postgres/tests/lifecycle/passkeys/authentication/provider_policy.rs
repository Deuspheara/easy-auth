use super::*;
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn provider_policy_rejects_preverified_passkey_and_new_account_bound_admission(pool: PgPool) {
    let mut f = SignIn::new(pool.clone()).await;
    let (transaction, response) = f.begin().await;
    let proof = f.proof(transaction, &response).await;
    let before: (Vec<u8>,i64,i64) = sqlx::query_as("SELECT credential,(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit) FROM auth_passkeys").fetch_one(&pool).await.unwrap();
    // Privileged policy transition fixture; no new public transition is exposed.
    sqlx::query("UPDATE auth_users SET authentication_policy='provider_required' WHERE realm_id=$1 AND id=$2").bind(f.enrollment.realm).bind(f.owner).execute(&pool).await.unwrap();
    assert!(matches!(
        f.enrollment
            .store
            .commit_authentication(
                &f.request(transaction),
                proof,
                Secret::generate().unwrap().verifier()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow
            .begin_account(f.owner, &f.enrollment.browser, SOURCE)
            .await,
        Err(Error::Unauthorized)
    ));
    let after: (Vec<u8>,i64,i64) = sqlx::query_as("SELECT credential,(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit) FROM auth_passkeys").fetch_one(&pool).await.unwrap();
    assert_eq!(before, after);
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkey_authentications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pending, 1);
}
