use super::*;

#[sqlx::test(migrations = "./migrations")]
async fn recovery_invalidates_bound_proofs_and_other_rp_codes_without_crossing_owner_or_realm(
    pool: PgPool,
) {
    let mut f = Replacement::new(pool.clone(), false).await;
    f.mature().await;
    let peer = Claims::in_realm(pool.clone(), false, Some(f.c.f.realm)).await;
    let other = Claims::new(pool.clone(), false).await;
    let other_before = other.snapshot().await;
    let (id, response) = f.assertion().await;
    let proof = f.proof(id, &response).await;
    let email_token = Secret::generate().unwrap();
    let email_browser = Secret::generate().unwrap();
    f.c.f
        .store
        .begin_email(
            f.c.f.realm,
            "alice@example.com",
            email_token.verifier(),
            email_browser.verifier(),
            [90; 32],
        )
        .await
        .unwrap();
    let setup =
        f.c.setup
            .prepare(&f.c.f.session, "pending-setup")
            .await
            .unwrap();
    let (deletion, deletion_browser) =
        crate::account::deletion_proof(&f.c.f.store, f.c.f.realm, f.c.f.session.verifier()).await;
    let other_rp = "other.example.com";
    sqlx::query("INSERT INTO auth_passkey_recovery_codes(realm_id,user_id,rp_id,version,code_hash) VALUES ($1,$2,$3,$4,$5)")
        .bind(f.c.f.realm).bind(f.c.owner).bind(other_rp).bind(Uuid::new_v4()).bind([91u8;32].as_slice()).execute(&pool).await.unwrap();
    f.c.f
        .store
        .commit_recovery_replacement(&f.request(id), proof, [92; 32])
        .await
        .unwrap();
    assert!(matches!(
        f.c.f
            .store
            .finish_email(
                f.c.f.realm,
                email_token.verifier(),
                email_browser.verifier(),
                [93; 32]
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.c.setup
            .confirm(&f.c.f.session, "pending-setup", setup.id, &setup.code)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.c.f
            .store
            .finish_account_deletion(
                f.c.f.realm,
                f.c.f.session.verifier(),
                deletion.verifier(),
                deletion_browser.verifier()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let remaining:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_passkey_recovery_codes WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3),(SELECT count(*) FROM auth_passkey_recovery_setups WHERE realm_id=$1 AND user_id=$2),(SELECT count(*) FROM auth_passkeys WHERE realm_id=$1 AND user_id=$2)")
        .bind(f.c.f.realm).bind(f.c.owner).bind(other_rp).fetch_one(&pool).await.unwrap();
    assert_eq!(remaining, (0, 0, 1));
    assert!(
        peer.f
            .store
            .authenticate(peer.f.realm, peer.f.session.verifier())
            .await
            .is_ok()
    );
    other.unchanged(other_before).await;
}
