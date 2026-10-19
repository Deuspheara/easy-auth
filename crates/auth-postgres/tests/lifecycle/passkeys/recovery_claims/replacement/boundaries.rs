use super::*;

#[sqlx::test(migrations = "./migrations")]
async fn every_replacement_stage_binds_browser_claim_owner_rp_realm_and_transaction(pool: PgPool) {
    let mut f = Replacement::new(pool.clone(), true).await;
    f.mature().await;
    let (id, registration) = f.registration().await;
    for mode in ["browser", "claim", "owner", "rp", "realm", "transaction"] {
        let mut request = f.request(id);
        match mode {
            "browser" => request.claim.browser = [43; 32],
            "claim" => request.claim_id = Uuid::new_v4(),
            "owner" => request.claim.user_id = Uuid::new_v4(),
            "rp" => request.claim.rp_id = "other.example.com".into(),
            "realm" => {
                let realm = Uuid::new_v4();
                f.c.f.store.ensure_realm(realm).await.unwrap();
                request.claim.realm = realm;
            }
            _ => request.transaction = Uuid::new_v4(),
        }
        assert!(
            matches!(
                f.c.f.store.load_recovery_registration(&request).await,
                Err(Error::Unauthorized)
            ),
            "exact bound registration context required"
        );
    }
    let assertion = f
        .flow
        .finish_registration(f.target, id, &f.c.browser, SOURCE, &registration)
        .await
        .unwrap();
    let signed = f
        .token
        .perform_auth(
            ORIGIN.parse().unwrap(),
            assertion.options.public_key,
            120_000,
        )
        .unwrap();
    let proof = f.proof(id, &signed).await;
    let mut request = f.request(id);
    request.claim.browser = [91; 32];
    let before = f.c.snapshot().await;
    assert!(matches!(
        f.c.f
            .store
            .commit_recovery_replacement(&request, proof, [88; 32])
            .await,
        Err(Error::Unauthorized)
    ));
    f.c.unchanged(before).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn candidate_restart_stales_old_proof_and_retains_original_claim_expiry(pool: PgPool) {
    let mut f = Replacement::new(pool.clone(), true).await;
    f.mature().await;
    let (old, response) = f.assertion().await;
    let proof = f.proof(old, &response).await;
    let expiry:i64=sqlx::query_scalar("SELECT (extract(epoch FROM expires_at)*1000000)::bigint FROM auth_passkey_recovery_claims WHERE realm_id=$1").bind(f.c.f.realm).fetch_one(&pool).await.unwrap();
    f.registration().await;
    let before = f.c.snapshot().await;
    assert!(matches!(
        f.c.f
            .store
            .commit_recovery_replacement(&f.request(old), proof, [21; 32])
            .await,
        Err(Error::Unauthorized)
    ));
    f.c.unchanged(before).await;
    let now:i64=sqlx::query_scalar("SELECT (extract(epoch FROM expires_at)*1000000)::bigint FROM auth_passkey_recovery_claims WHERE realm_id=$1").bind(f.c.f.realm).fetch_one(&pool).await.unwrap();
    assert_eq!(expiry, now);
}

#[sqlx::test(migrations = "./migrations")]
async fn cancelled_rotated_deleted_or_expired_claims_cannot_commit_preverified_proofs(
    pool: PgPool,
) {
    for mode in ["cancel", "rotate", "delete", "expire", "candidate_expire"] {
        let mut f = Replacement::new(pool.clone(), mode != "delete").await;
        f.mature().await;
        let (id, response) = f.assertion().await;
        let proof = f.proof(id, &response).await;
        match mode {
            "cancel" => {
                f.c.flow
                    .cancel(f.c.owner, &f.c.browser, SOURCE, f.target.claim_id)
                    .await
                    .unwrap()
            }
            "rotate" => {
                let new = f.c.setup.prepare(&f.c.f.session, "rotate").await.unwrap();
                f.c.setup
                    .confirm(&f.c.f.session, "rotate", new.id, &new.code)
                    .await
                    .unwrap();
            }
            "delete" => {
                let (token, browser) = crate::account::deletion_proof(
                    &f.c.f.store,
                    f.c.f.realm,
                    f.c.f.session.verifier(),
                )
                .await;
                f.c.f
                    .store
                    .finish_account_deletion(
                        f.c.f.realm,
                        f.c.f.session.verifier(),
                        token.verifier(),
                        browser.verifier(),
                    )
                    .await
                    .unwrap();
            }
            "expire" => {
                sqlx::query("UPDATE auth_passkey_recovery_claims SET expires_at=clock_timestamp()-interval '1 second' WHERE realm_id=$1").bind(f.c.f.realm).execute(&pool).await.unwrap();
            }
            _ => {
                sqlx::query("UPDATE auth_passkey_recovery_replacements SET expires_at=clock_timestamp()-interval '1 second' WHERE realm_id=$1").bind(f.c.f.realm).execute(&pool).await.unwrap();
            }
        }
        let before = f.c.snapshot().await;
        assert!(matches!(
            f.c.f
                .store
                .commit_recovery_replacement(&f.request(id), proof, [44; 32])
                .await,
            Err(Error::Unauthorized)
        ));
        f.c.unchanged(before).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn bad_assertion_never_becomes_recovery_and_valid_retry_succeeds(pool: PgPool) {
    let mut f = Replacement::new(pool, true).await;
    f.mature().await;
    let (id, response) = f.assertion().await;
    let mut bad = serde_json::to_value(&response).unwrap();
    bad["response"]["clientDataJSON"] = "e30".into();
    let bad = serde_json::from_value(bad).unwrap();
    let before = f.c.snapshot().await;
    assert!(matches!(
        f.flow
            .finish(f.target, id, &f.c.browser, SOURCE, &bad)
            .await,
        Err(Error::Unauthorized)
    ));
    f.c.unchanged(before).await;
    assert!(
        f.flow
            .finish(f.target, id, &f.c.browser, SOURCE, &response)
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn preverified_old_key_cannot_issue_a_session_after_recovery(pool: PgPool) {
    use auth_core::{PasskeyAuthenticationRepository, PasskeyAuthenticationRequest, PasskeySignIn};
    let mut f = Replacement::new(pool.clone(), true).await;
    f.mature().await;
    let signin = PasskeySignIn::new(f.c.f.realm, f.c.f.service.clone(), f.c.f.store.clone());
    let pending = signin
        .begin_account(f.c.owner, &f.c.browser, "old-key")
        .await
        .unwrap();
    let response =
        f.c.token
            .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
            .unwrap();
    let request = PasskeyAuthenticationRequest {
        realm: f.c.f.realm,
        transaction: pending.transaction,
        browser: f.c.browser.verifier(),
        source: [71; 32],
    };
    let hint =
        f.c.f
            .service
            .authentication_credential_id(&response)
            .unwrap();
    let (state, key) =
        f.c.f
            .store
            .load_authentication(&request, f.c.f.service.rp_id(), hint)
            .await
            .unwrap();
    let proof =
        f.c.f
            .service
            .verify_authentication(&response, state, key)
            .unwrap();
    let (id, response) = f.assertion().await;
    f.flow
        .finish(f.target, id, &f.c.browser, SOURCE, &response)
        .await
        .unwrap();
    let before = f.c.snapshot().await;
    assert!(matches!(
        f.c.f
            .store
            .commit_authentication(&request, proof, [72; 32])
            .await,
        Err(Error::Unauthorized)
    ));
    f.c.unchanged(before).await;
}
