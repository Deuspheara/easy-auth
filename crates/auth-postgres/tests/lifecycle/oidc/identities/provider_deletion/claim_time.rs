use super::completion_setup::{account, fresh, snapshot};
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn signed_future_authentication_time_is_rejected_before_any_deletion_proof_exists(
    pool: PgPool,
) {
    let (f, user, current) = account(pool).await;
    let before = snapshot(&f).await;
    let now = f.now_seconds().await;
    let result = f
        .try_mapped_for(
            "owned",
            json!({"auth_time":now+60}),
            OAuthPurpose::DeleteProviderAccount {
                user: user.id,
                session: current.verifier(),
            },
            None,
        )
        .await;
    assert!(
        matches!(result, Err(Error::Unauthorized)),
        "the actual signature/claim verifier, not deletion, rejects a future claim"
    );
    assert!(
        f.now_seconds().await < now + 30,
        "test infrastructure: this negative must not cross the token/transaction cap"
    );
    assert!(snapshot(&f).await == before);
    OidcAccountDeletion::new(f.store.clone())
        .finish(fresh(&f, &user, &current).await)
        .await
        .unwrap();
}
