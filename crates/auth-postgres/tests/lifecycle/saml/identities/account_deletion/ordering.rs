use super::setup::{Fixture, counts, proof};
use auth_core::{Error, Repository, SamlAccountDeletion, SamlSignIn};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn two_sequentially_verified_deletions_have_one_database_winner(pool: PgPool) {
    let f = Fixture::new(pool).await;
    // Finish both native verifications before the database-only ordering.
    let first = proof(&f, "normal").await;
    let second = proof(&f, "normal").await;
    let service = SamlAccountDeletion::new(f.source.store.clone());
    let (first, second) = tokio::join!(service.finish(first), service.finish(second));
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(matches!(
        first.err().or(second.err()),
        Some(Error::Unauthorized)
    ));
    assert_eq!(counts(&f).await, (0, 0, 0, 4, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn deletion_and_preverified_sign_in_cannot_leave_or_recreate_local_authority(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let signin = f
        .policy
        .map(super::super::setup::verify(&f.source, "normal").await)
        .unwrap();
    let deletion = proof(&f, "normal").await;
    let deletes = SamlAccountDeletion::new(f.source.store.clone());
    let signs_in = SamlSignIn::new(f.source.store.clone());
    let (deleted, signed_in) = tokio::join!(deletes.finish(deletion), signs_in.finish(signin));
    deleted.unwrap();
    let extra = match signed_in {
        Ok((_, bearer)) => {
            assert!(matches!(
                f.source
                    .store
                    .authenticate(f.user.realm_id, bearer.verifier())
                    .await,
                Err(Error::Unauthorized)
            ));
            1
        }
        Err(Error::Unauthorized) => 0,
        Err(_) => panic!("infrastructure failure is not an expected ordering outcome"),
    };
    assert_eq!(counts(&f).await, (0, 0, 0, 4 + 2 * extra, 2 + extra, 0));
}
