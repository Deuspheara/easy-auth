use super::*;
use auth_core::{Error, PasskeyManagementRepository, PasskeyManagementRequest, SecurityNoticeKind};

#[sqlx::test(migrations = "./migrations")]
async fn genuine_proof_controls_inventory_rename_and_verified_contact_notices(pool: PgPool) {
    for email_free in [false, true] {
        let f = Management::new(pool.clone(), email_free).await;
        let key = f.keys().await.remove(0);
        assert!(key.last_used_at_ms.is_some());
        let projected = serde_json::to_value(&key).unwrap();
        assert_eq!(projected.as_object().unwrap().len(), 5);
        for field in [
            "credential",
            "credential_id",
            "rp_id",
            "user_id",
            "realm_id",
        ] {
            assert!(projected.get(field).is_none());
        }
        let next = f
            .flow
            .rename(&f.session, SOURCE, key.id, key.version, "Renamed key")
            .await
            .unwrap();
        assert_ne!(next, key.version);
        let renamed = f.key(key.id).await;
        assert_eq!(renamed.version, next);
        assert_eq!(renamed.label, "Renamed key");
        assert!(matches!(
            f.flow
                .rename(&f.session, SOURCE, key.id, key.version, "Stale write")
                .await,
            Err(Error::Unauthorized)
        ));
        let notice = f
            .fixture
            .store
            .claim_security_notice(f.fixture.realm)
            .await
            .unwrap();
        if email_free {
            assert!(notice.is_none());
        } else {
            let notice = notice.unwrap();
            assert!(matches!(notice.kind, SecurityNoticeKind::PasskeysChanged));
            f.fixture
                .store
                .complete_security_notice(f.fixture.realm, notice.id, notice.lease, false)
                .await
                .unwrap();
            let attempts: i32 =
                sqlx::query_scalar("SELECT attempts FROM auth_security_notifications WHERE id=$1")
                    .bind(notice.id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(attempts, 1);
        }
        let audited: Uuid = sqlx::query_scalar(
            "SELECT passkey_id FROM auth_audit WHERE realm_id=$1 AND kind='passkey_renamed'",
        )
        .bind(f.fixture.realm)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audited, key.id);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn weak_methods_stale_future_idle_and_absolute_authority_cannot_manage(pool: PgPool) {
    let f = Management::new(pool.clone(), false).await;
    let key = f.keys().await.remove(0);
    assert!(matches!(
        f.flow
            .rename(
                &f.fixture.session,
                SOURCE,
                key.id,
                key.version,
                "Mailbox denied"
            )
            .await,
        Err(Error::Unauthorized)
    ));
    for method in ["email", "password", "legacy_unknown"] {
        sqlx::query("UPDATE auth_sessions SET authentication_method=$2 WHERE token_hash=$1")
            .bind(f.session.verifier().as_slice())
            .bind(method)
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            f.flow.list(&f.session, SOURCE).await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            f.flow.remove(&f.session, SOURCE, key.id, key.version).await,
            Err(Error::Unauthorized)
        ));
    }
    for update in [
        "authenticated_at=clock_timestamp()-interval '6 minutes'",
        "authenticated_at=clock_timestamp()+interval '1 minute'",
        "last_seen_at=clock_timestamp()-interval '31 minutes'",
        "expires_at=clock_timestamp()-interval '1 second'",
    ] {
        sqlx::query("UPDATE auth_sessions SET authentication_method='passkey',authenticated_at=clock_timestamp(),last_seen_at=clock_timestamp(),expires_at=clock_timestamp()+interval '1 day' WHERE token_hash=$1")
            .bind(f.session.verifier().as_slice()).execute(&pool).await.unwrap();
        sqlx::query(&format!(
            "UPDATE auth_sessions SET {update} WHERE token_hash=$1"
        ))
        .bind(f.session.verifier().as_slice())
        .execute(&pool)
        .await
        .unwrap();
        assert!(matches!(
            f.flow.list(&f.session, SOURCE).await,
            Err(Error::Unauthorized)
        ));
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn owner_realm_rp_and_version_never_widen_key_selection(pool: PgPool) {
    let f = Management::new(pool.clone(), true).await;
    let other = Management::new(pool.clone(), true).await;
    let key = other.keys().await.remove(0);
    let before = other.snapshot().await;
    assert!(matches!(
        f.flow
            .rename(&f.session, SOURCE, key.id, key.version, "Foreign")
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow.remove(&f.session, SOURCE, key.id, key.version).await,
        Err(Error::Unauthorized)
    ));
    for wrong_realm in [false, true] {
        let request = PasskeyManagementRequest {
            realm: if wrong_realm {
                other.fixture.realm
            } else {
                f.fixture.realm
            },
            session: f.session.verifier(),
            rp_id: "other.example.com".into(),
            source: [2; 32],
        };
        let result = f.fixture.store.list_passkeys(&request).await;
        if wrong_realm {
            assert!(matches!(result, Err(Error::Unauthorized)));
        } else {
            assert!(result.unwrap().is_empty());
        }
        assert!(matches!(
            f.fixture
                .store
                .rename_passkey(&request, key.id, key.version, "Foreign")
                .await,
            Err(Error::Unauthorized)
        ));
    }
    // A distinct owner in the SAME realm must also be excluded.
    let peer =
        crate::support::signed_in(&f.fixture.store, f.fixture.realm, "peer@example.test").await;
    let pending = f
        .fixture
        .enrollment
        .begin(&peer, &f.fixture.browser, SOURCE, "Peer key")
        .await
        .unwrap();
    let (mut token, _) = SoftToken::new(true).unwrap();
    let response = token
        .perform_register(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
        .unwrap();
    let id = f
        .fixture
        .enrollment
        .finish(
            &peer,
            &f.fixture.browser,
            SOURCE,
            pending.transaction,
            &response,
        )
        .await
        .unwrap();
    let version: Uuid = sqlx::query_scalar(
        "SELECT management_version FROM auth_passkeys WHERE realm_id=$1 AND id=$2",
    )
    .bind(f.fixture.realm)
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(matches!(
        f.flow
            .rename(&f.session, SOURCE, id, version, "Denied")
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow.remove(&f.session, SOURCE, id, version).await,
        Err(Error::Unauthorized)
    ));
    let label: String =
        sqlx::query_scalar("SELECT label FROM auth_passkeys WHERE realm_id=$1 AND id=$2")
            .bind(f.fixture.realm)
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(label, "Peer key");
    other.assert_unchanged(before).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn removal_requires_a_proven_remaining_key_and_revokes_sessions(pool: PgPool) {
    let f = Management::new(pool.clone(), true).await;
    let first = f.keys().await.remove(0);
    assert!(matches!(
        f.flow
            .remove(&f.session, SOURCE, first.id, first.version)
            .await,
        Err(Error::Unauthorized)
    ));
    let (second, mut token) = f.add_key("Spare key").await;
    assert!(f.key(second).await.last_used_at_ms.is_none());
    assert!(matches!(
        f.flow
            .remove(&f.session, SOURCE, first.id, first.version)
            .await,
        Err(Error::Unauthorized)
    ));
    let spare_session = f.sign_in(&mut token).await;
    f.flow
        .remove(&f.session, SOURCE, first.id, first.version)
        .await
        .unwrap();
    for session in [&f.session, &spare_session, &f.fixture.session] {
        assert!(matches!(
            f.fixture
                .store
                .authenticate(f.fixture.realm, session.verifier())
                .await,
            Err(Error::Unauthorized)
        ));
    }
    let fresh = f.sign_in(&mut token).await;
    assert!(
        f.fixture
            .store
            .authenticate(f.fixture.realm, fresh.verifier())
            .await
            .is_ok()
    );
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE realm_id=$1 AND user_id=$2")
            .bind(f.fixture.realm)
            .bind(f.owner)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 1);
}
