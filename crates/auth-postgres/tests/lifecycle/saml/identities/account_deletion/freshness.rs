use super::setup::{Fixture, counts, proof};
use auth_core::{Error, SamlAccountDeletion};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn actual_signed_authentication_has_closed_future_and_stale_policy_boundaries_without_grant(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let input = proof(&f, "normal").await;
    let authenticated = input.assertion().authenticated_at_us();
    let expires = input.fresh_until_us();
    // Ordinary pure policy observations of this real proof. No signature facts,
    // XML, database clock or cryptographic verifier are replaced or modified.
    for observed in [authenticated - 1, expires, expires + 1] {
        assert!(matches!(
            input.validate_authentication_at(observed),
            Err(Error::Unauthorized)
        ));
    }
    for observed in [authenticated, expires - 1] {
        input.validate_authentication_at(observed).unwrap();
    }
    assert_eq!(counts(&f).await, (1, 1, 1, 2, 1, 0));
    let now: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&f.source.pool)
            .await
            .unwrap();
    input.validate_authentication_at(now).unwrap();
    SamlAccountDeletion::new(f.source.store.clone())
        .finish(input)
        .await
        .unwrap();
    assert_eq!(counts(&f).await, (0, 0, 0, 4, 2, 0));
}
