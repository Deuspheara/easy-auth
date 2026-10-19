use super::super::ORIGIN;
use super::*;
use auth_core::PasskeySignIn;
use webauthn_authenticator_rs::AuthenticatorBackend;

#[sqlx::test(migrations = "./migrations")]
async fn another_genuinely_authenticated_owner_cannot_confirm_an_owned_setup(pool: PgPool) {
    let f = Setup::new(pool.clone(), false).await;
    let code = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
    let peer = crate::support::signed_in(&f.f.store, f.f.realm, "peer@example.test").await;
    let peer_id =
        f.f.store
            .authenticate(f.f.realm, peer.verifier())
            .await
            .unwrap()
            .id;
    let pending =
        f.f.enrollment
            .begin(&peer, &f.f.browser, SOURCE, "Peer key")
            .await
            .unwrap();
    let (mut token, _) = SoftToken::new(true).unwrap();
    let response = token
        .perform_register(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
        .unwrap();
    f.f.enrollment
        .finish(&peer, &f.f.browser, SOURCE, pending.transaction, &response)
        .await
        .unwrap();
    let sign_in = PasskeySignIn::new(f.f.realm, f.f.service.clone(), f.f.store.clone());
    let pending = sign_in
        .begin_account(peer_id, &f.f.browser, SOURCE)
        .await
        .unwrap();
    let response = token
        .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
        .unwrap();
    let peer = sign_in
        .finish(&f.f.browser, SOURCE, pending.transaction, &response)
        .await
        .unwrap();
    let mut request = f.request();
    request.session = peer.verifier();
    let snapshot = f.snapshot().await;
    assert!(matches!(
        f.f.store
            .confirm_passkey_recovery_code(&request, code.id, code.code.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    f.unchanged(snapshot).await;
    f.flow
        .confirm(&f.f.session, SOURCE, code.id, &code.code)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn configuration_requires_a_proven_key_in_the_configured_rp(pool: PgPool) {
    let f = Setup::new(pool.clone(), false).await;
    let mut request = f.request();
    request.rp_id = "other.example.com".into();
    let hash = Secret::generate().unwrap().verifier();
    assert!(matches!(
        f.f.store
            .prepare_passkey_recovery_code(&request, Uuid::new_v4(), hash)
            .await,
        Err(Error::Unauthorized)
    ));
    let pending = f.flow.prepare(&f.f.session, SOURCE).await.unwrap();
    // Negative storage fixture: a session timestamp cannot replace key-use evidence.
    sqlx::query("UPDATE auth_passkeys SET last_used_at=NULL WHERE realm_id=$1")
        .bind(f.f.realm)
        .execute(&pool)
        .await
        .unwrap();
    let snapshot = f.snapshot().await;
    assert!(matches!(
        f.flow.prepare(&f.f.session, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow
            .confirm(&f.f.session, SOURCE, pending.id, &pending.code)
            .await,
        Err(Error::Unauthorized)
    ));
    f.unchanged(snapshot).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn deletion_erases_setup_active_code_and_audit_attribution_only_for_its_owner(pool: PgPool) {
    let f = Setup::new(pool.clone(), false).await;
    let other = Setup::new(pool.clone(), false).await;
    for owner in [&f, &other] {
        let code = owner.flow.prepare(&owner.f.session, SOURCE).await.unwrap();
        owner
            .flow
            .confirm(&owner.f.session, SOURCE, code.id, &code.code)
            .await
            .unwrap();
        owner.flow.prepare(&owner.f.session, SOURCE).await.unwrap();
    }
    let before = other.snapshot().await;
    let (token, browser) =
        crate::account::deletion_proof(&f.f.store, f.f.realm, f.f.session.verifier()).await;
    f.f.store
        .finish_account_deletion(
            f.f.realm,
            f.f.session.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    assert!(f.active().await.is_none());
    assert_eq!(f.counts().await, (0, 1, 0));
    let erased: bool = sqlx::query_scalar("SELECT subject_erased AND user_id IS NULL AND actor_session_id IS NULL AND session_id IS NULL AND passkey_id IS NULL FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovery_configured'")
        .bind(f.f.realm).fetch_one(&pool).await.unwrap();
    assert!(erased);
    other.unchanged(before).await;
}
