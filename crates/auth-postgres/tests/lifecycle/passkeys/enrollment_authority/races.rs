use super::*;
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn competing_mailbox_bootstrap_proofs_cannot_commit_two_initial_keys(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (a, encoded_a, proof_a) = prepare(&f).await;
    let (b, encoded_b, proof_b) = prepare(&f).await;
    let (a, b) = tokio::join!(
        f.store.commit_enrollment(&a, &encoded_a, proof_a),
        f.store.commit_enrollment(&b, &encoded_b, proof_b)
    );
    assert!(
        matches!(
            (&a, &b),
            (Ok(_), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(_))
        ),
        "only one mailbox-bootstrap authority can commit; infrastructure errors are not an accepted loser"
    );
    assert_eq!(counts(&pool, f.realm).await, (1, 1, 1));
}
