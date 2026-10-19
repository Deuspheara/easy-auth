use super::*;
use auth_core::{Error, PasskeyEnrollmentStart};

#[sqlx::test(migrations = "./migrations")]
async fn existing_key_requires_actual_passkey_method_at_context_save_load_and_commit(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (old_request, old_state, old_proof) = prepare(&f).await;
    let context = f
        .store
        .enrollment_context(f.realm, f.session.verifier(), f.service.rp_id())
        .await
        .unwrap();
    let (_, new_state) = f
        .service
        .begin_registration(
            context.user_id,
            &context.account_name,
            &context.excluded_credentials,
        )
        .unwrap();
    let mut token = first_key(&f).await;
    for method in ["email", "password", "legacy_unknown"] {
        sqlx::query(
            "UPDATE auth_sessions SET authentication_method=$2 WHERE realm_id=$1 AND token_hash=$3",
        )
        .bind(f.realm)
        .bind(method)
        .bind(f.session.verifier().as_slice())
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            matches!(
                f.store
                    .enrollment_context(f.realm, f.session.verifier(), f.service.rp_id())
                    .await,
                Err(Error::Unauthorized)
            ),
            "existing credentials require a genuine passkey method, not only a recent timestamp"
        );
        assert!(
            matches!(
                f.store.load_enrollment(&old_request).await,
                Err(Error::Unauthorized)
            ),
            "a preissued mailbox ceremony cannot be verified after another key commits"
        );
    }
    // Reset only the original mailbox fixture method, never fabricate passkey proof.
    sqlx::query("UPDATE auth_sessions SET authentication_method='email' WHERE realm_id=$1 AND token_hash=$2")
        .bind(f.realm).bind(f.session.verifier().as_slice()).execute(&pool).await.unwrap();
    let pending = PasskeyEnrollmentStart {
        request: f.request(Uuid::new_v4()),
        user_id: context.user_id,
        rp_id: f.service.rp_id().into(),
        label: "Stale preflight".into(),
        state: new_state,
    };
    assert!(
        matches!(
            f.store.save_enrollment(pending).await,
            Err(Error::Unauthorized)
        ),
        "preflight context is not authority to save after a key appears"
    );
    assert!(
        matches!(
            f.store
                .commit_enrollment(&old_request, &old_state, old_proof)
                .await,
            Err(Error::Unauthorized)
        ),
        "a proof verified before another key commits must recheck additional-enrollment authority"
    );
    assert_eq!(counts(&pool, f.realm).await, (1, 1, 1));
    let proven = sign_in(&f, &mut token).await;
    assert_eq!(
        f.store
            .enrollment_context(f.realm, proven.verifier(), f.service.rp_id())
            .await
            .unwrap()
            .excluded_credentials
            .len(),
        1
    );
    let pending = f
        .enrollment
        .begin(&proven, &f.browser, SOURCE, "Proven additional key")
        .await
        .unwrap();
    let response = register(pending.options, ORIGIN, true);
    f.enrollment
        .finish(&proven, &f.browser, SOURCE, pending.transaction, &response)
        .await
        .unwrap();
    assert_eq!(counts(&pool, f.realm).await, (2, 2, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn keys_in_another_rp_still_require_method_proof_but_other_users_and_realms_do_not(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone()).await;
    first_key(&f).await;
    let other_service =
        Arc::new(PasskeyService::new("https://other.example.com", "Other RP").unwrap());
    assert!(matches!(
        f.store
            .enrollment_context(f.realm, f.session.verifier(), other_service.rp_id())
            .await,
        Err(Error::Unauthorized)
    ));
    let peer = signed_in(&f.store, f.realm, "peer@example.test").await;
    assert!(
        f.store
            .enrollment_context(f.realm, peer.verifier(), other_service.rp_id())
            .await
            .is_ok()
    );
    let other = Uuid::new_v4();
    f.store.ensure_realm(other).await.unwrap();
    let foreign = signed_in(&f.store, other, "alice@example.com").await;
    assert!(
        f.store
            .enrollment_context(other, foreign.verifier(), f.service.rp_id())
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_legacy_method_cannot_bootstrap_from_a_recent_timestamp(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    // Migration/storage scenario: recent time does not establish a known method.
    sqlx::query(
        "UPDATE auth_sessions SET authentication_method='legacy_unknown' WHERE realm_id=$1",
    )
    .bind(f.realm)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        f.store
            .enrollment_context(f.realm, f.session.verifier(), f.service.rp_id())
            .await,
        Err(auth_core::Error::Unauthorized)
    ));
    assert_eq!(counts(&pool, f.realm).await, (0, 0, 0));
}
