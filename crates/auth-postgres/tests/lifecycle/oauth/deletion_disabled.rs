use super::{linking::signed_in_owner, setup::Fixture};
use auth_core::{Error, OAuthPurpose, Repository};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn provider_deletion_purpose_fails_closed_without_identity_feature(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (user, session) = signed_in_owner(&f).await;
    let result = f
        .flow
        .begin(&f.intent(OAuthPurpose::DeleteProviderAccount {
            user,
            session: session.verifier(),
        }))
        .await;
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.pending().await, 0);
    assert_eq!(
        f.store
            .authenticate(f.connection.realm(), session.verifier())
            .await
            .unwrap()
            .id,
        user
    );
    let normal = f.start().await;
    f.flow
        .cancel(
            &f.intent(OAuthPurpose::SignIn),
            &normal.state,
            &normal.proof,
        )
        .await
        .unwrap();
}
