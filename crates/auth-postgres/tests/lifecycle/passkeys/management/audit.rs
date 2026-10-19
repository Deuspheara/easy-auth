use super::*;

#[sqlx::test(migrations = "./migrations")]
async fn account_deletion_erases_key_target_attribution_without_touching_other_realms(
    pool: PgPool,
) {
    let f = Management::new(pool.clone(), false).await;
    let other = Management::new(pool.clone(), false).await;
    for owner in [&f, &other] {
        let key = owner.keys().await.remove(0);
        owner
            .flow
            .rename(&owner.session, SOURCE, key.id, key.version, "Renamed")
            .await
            .unwrap();
    }
    let before = other.snapshot().await;
    let (token, browser) =
        crate::account::deletion_proof(&f.fixture.store, f.fixture.realm, f.session.verifier())
            .await;
    f.fixture
        .store
        .finish_account_deletion(
            f.fixture.realm,
            f.session.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    let erased: bool = sqlx::query_scalar("SELECT subject_erased AND user_id IS NULL AND actor_session_id IS NULL AND passkey_id IS NULL FROM auth_audit WHERE realm_id=$1 AND kind='passkey_renamed'")
        .bind(f.fixture.realm).fetch_one(&pool).await.unwrap();
    assert!(erased);
    other.assert_unchanged(before).await;
}
