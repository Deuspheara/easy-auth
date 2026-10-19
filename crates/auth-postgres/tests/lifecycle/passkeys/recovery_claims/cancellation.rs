use super::*;

#[sqlx::test(migrations = "./migrations")]
async fn retained_saved_code_can_only_cancel_after_every_session_is_revoked(pool: PgPool) {
    let f = Claims::new(pool.clone(), false).await;
    let claim = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    f.f.store
        .revoke_all_sessions(f.f.realm, f.f.session.verifier())
        .await
        .unwrap();
    assert!(matches!(
        f.f.store
            .authenticate(f.f.realm, f.f.session.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    let wrong = Secret::generate().unwrap();
    assert!(matches!(
        f.flow.cancel_with_code(f.owner, &wrong, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    f.flow
        .cancel_with_code(f.owner, &f.code, SOURCE)
        .await
        .unwrap();
    assert!(matches!(
        f.flow.resume(f.owner, &f.browser, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow.begin(f.owner, &f.code, &f.browser, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    let another = Secret::generate().unwrap();
    assert!(matches!(
        f.flow.begin(f.owner, &f.code, &another, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    let fact:bool=sqlx::query_scalar("SELECT actor_session_id IS NULL AND session_id IS NULL AND recovery_claim_id=$2 FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovery_cancelled'")
        .bind(f.f.realm).bind(claim.id).fetch_one(&pool).await.unwrap();
    assert!(fact);
    assert!(matches!(
        f.f.store
            .authenticate(f.f.realm, f.browser.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn preplayed_cancellation_and_code_guessing_cannot_exhaust_an_alerted_owners_deny_path(
    pool: PgPool,
) {
    let f = Claims::new(pool, false).await;
    for _ in 0..10 {
        assert!(matches!(
            f.flow.cancel_with_code(f.owner, &f.code, "192.0.2.1").await,
            Err(Error::Unauthorized)
        ));
    }
    let wrong = Secret::generate().unwrap();
    for _ in 0..8 {
        assert!(matches!(
            f.flow.begin(f.owner, &wrong, &f.browser, SOURCE).await,
            Err(Error::Unauthorized)
        ));
    }
    f.flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    assert!(matches!(
        f.flow.begin(f.owner, &wrong, &f.browser, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow.begin(f.owner, &f.code, &f.browser, SOURCE).await,
        Err(Error::RateLimited)
    ));
    // A separate trusted transport source models the alerted owner; no account
    // or submitted-code counter can be pre-exhausted to preserve a fraudulent claim.
    f.flow
        .cancel_with_code(f.owner, &f.code, "192.0.2.2")
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn browser_cancellation_does_not_revive_a_code_or_mint_a_session(pool: PgPool) {
    let f = Claims::new(pool.clone(), false).await;
    let claim = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    f.flow
        .cancel(f.owner, &f.browser, SOURCE, claim.id)
        .await
        .unwrap();
    let snapshot = f.snapshot().await;
    assert!(matches!(
        f.flow.status(f.owner, &f.browser, SOURCE, claim.id).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow.begin(f.owner, &f.code, &f.browser, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    f.unchanged(snapshot).await;
    let fact:bool=sqlx::query_scalar("SELECT actor_session_id IS NULL AND session_id IS NULL AND recovery_claim_id=$2 FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovery_cancelled'")
        .bind(f.f.realm).bind(claim.id).fetch_one(&pool).await.unwrap();
    assert!(fact);
    let notice =
        f.f.store
            .claim_security_notice(f.f.realm)
            .await
            .unwrap()
            .unwrap();
    assert!(matches!(
        notice.kind,
        SecurityNoticeKind::PasskeyRecoveryCancelled
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn fresh_key_cancellation_derives_owner_and_denies_weaker_or_foreign_sessions(pool: PgPool) {
    let f = Claims::new(pool.clone(), false).await;
    let peer = Claims::in_realm(pool.clone(), false, Some(f.f.realm)).await;
    let claim = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    assert!(matches!(
        peer.flow
            .cancel_with_key(&peer.f.session, SOURCE, claim.id)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow.cancel_with_key(&f.weak, SOURCE, claim.id).await,
        Err(Error::Unauthorized)
    ));
    f.flow
        .cancel_with_key(&f.f.session, SOURCE, claim.id)
        .await
        .unwrap();
    let actor:bool=sqlx::query_scalar("SELECT a.actor_session_id=s.id AND a.recovery_claim_id=$3 AND s.authentication_method='passkey' FROM auth_audit a JOIN auth_sessions s ON s.realm_id=a.realm_id AND s.user_id=a.user_id WHERE a.realm_id=$1 AND s.token_hash=$2 AND a.kind='passkey_recovery_cancelled'")
        .bind(f.f.realm).bind(f.f.session.verifier().as_slice()).bind(claim.id).fetch_one(&pool).await.unwrap();
    assert!(actor);
}

#[sqlx::test(migrations = "./migrations")]
async fn audit_or_notice_failure_rolls_back_code_reservation_and_cancellation(pool: PgPool) {
    let f = Claims::new(pool.clone(), false).await;
    for mode in [
        "start_audit",
        "start_notice",
        "cancel_audit",
        "cancel_notice",
    ] {
        let claim = if mode.starts_with("cancel") {
            Some(
                f.flow
                    .begin(f.owner, &f.code, &f.browser, SOURCE)
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let (table, kind) = match mode {
            "start_audit" => ("auth_audit", "passkey_recovery_started"),
            "start_notice" => ("auth_security_notifications", "passkey_recovery_started"),
            "cancel_audit" => ("auth_audit", "passkey_recovery_cancelled"),
            "cancel_notice" => ("auth_security_notifications", "passkey_recovery_cancelled"),
            _ => unreachable!(),
        };
        let snapshot = f.snapshot().await;
        sqlx::raw_sql(&format!("CREATE OR REPLACE FUNCTION fail_recovery_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='{kind}' THEN RAISE EXCEPTION 'controlled recovery failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_recovery_claim BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION fail_recovery_claim();"))
            .execute(&pool).await.unwrap();
        if let Some(claim) = claim {
            assert!(matches!(
                f.flow.cancel(f.owner, &f.browser, SOURCE, claim.id).await,
                Err(Error::Unavailable)
            ));
        } else {
            assert!(matches!(
                f.flow.begin(f.owner, &f.code, &f.browser, SOURCE).await,
                Err(Error::Unavailable)
            ));
        }
        f.unchanged(snapshot).await;
        sqlx::raw_sql(&format!("DROP TRIGGER fail_recovery_claim ON {table}"))
            .execute(&pool)
            .await
            .unwrap();
    }
    let live = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    f.flow
        .cancel(f.owner, &f.browser, SOURCE, live.id)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn alerted_owner_can_cancel_current_claim_with_a_key_without_knowing_claim_id(pool: PgPool) {
    let f = Claims::new(pool.clone(), false).await;
    let claim = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    assert!(matches!(
        f.flow.cancel_current_with_key(&f.weak, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    f.flow
        .cancel_current_with_key(&f.f.session, SOURCE)
        .await
        .unwrap();
    assert!(matches!(
        f.flow.status(f.owner, &f.browser, SOURCE, claim.id).await,
        Err(Error::Unauthorized)
    ));
    let facts:i64=sqlx::query_scalar("SELECT count(*) FROM auth_audit a JOIN auth_sessions s ON s.realm_id=a.realm_id AND s.id=a.actor_session_id AND s.user_id=a.user_id WHERE a.realm_id=$1 AND a.user_id=$2 AND a.kind='passkey_recovery_cancelled' AND a.recovery_claim_id=$3 AND s.authentication_method='passkey'")
        .bind(f.f.realm).bind(f.owner).bind(claim.id).fetch_one(&pool).await.unwrap();
    assert_eq!(facts, 1);
}
