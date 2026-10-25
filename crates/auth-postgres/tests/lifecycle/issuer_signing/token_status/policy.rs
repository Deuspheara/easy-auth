use super::*;
use auth_core::{IssuerTokenError, Repository};

#[sqlx::test]
async fn original_consent_code_caps_cannot_be_extended_by_the_access_ledger(pool: PgPool) {
    let f = Fixture::new(pool, true).await;
    assert!(
        f.service()
            .introspect_access(
                &f.authentication(),
                &f.issued.access_token().into(),
                "127.0.0.1"
            )
            .await
            .unwrap()
            .is_some()
    );
    // Keep a valid consumed-row shape while narrowing its original code cap.
    // The opaque access record must not override original grant authority.
    sqlx::query("UPDATE auth_issuer_authorizations SET code_expires_at_us=consumed_at_us+1 WHERE realm_id=$1 AND status='consumed'")
        .bind(f.f.authority.realm()).execute(&f.f.pool).await.unwrap();
    assert!(
        f.service()
            .introspect_access(
                &f.authentication(),
                &f.issued.access_token().into(),
                "127.0.0.1"
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(f.revoked().await.is_none());
}

#[sqlx::test]
async fn retained_original_key_allows_live_access_after_ordinary_active_key_rotation(pool: PgPool) {
    let f = Fixture::new(pool, true).await;
    let current = f.f.store.load_issuer_signing(&f.f.authority).await.unwrap();
    let replacement = super::super::alias(current.publication());
    f.f.store.publish_issuer_key(&replacement).await.unwrap();
    super::super::allow_rotation(&f.f.pool, &replacement).await;
    f.f.store
        .activate_issuer_key(&f.f.authority, replacement.key().id())
        .await
        .unwrap();
    // Metadata-only selection after the original signature is complete. No
    // signature mutation, fallback signer or concurrent cryptographic work.
    assert!(
        f.service()
            .introspect_access(
                &f.authentication(),
                &f.issued.access_token().into(),
                "127.0.0.1"
            )
            .await
            .unwrap()
            .is_some()
    );
    f.f.store
        .disable_issuer_key(&f.f.authority, f.f.key.id())
        .await
        .unwrap();
    assert!(
        f.service()
            .introspect_access(
                &f.authentication(),
                &f.issued.access_token().into(),
                "127.0.0.1"
            )
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test]
async fn current_session_key_namespace_and_owner_policy_revoke_active_metadata(pool: PgPool) {
    for change in ["session", "key", "issuer", "owner"] {
        let f = Fixture::new(pool.clone(), true).await;
        assert!(
            f.service()
                .introspect_access(
                    &f.authentication(),
                    &f.issued.access_token().into(),
                    "127.0.0.1"
                )
                .await
                .unwrap()
                .is_some()
        );
        match change {
            "session" => {
                f.f.store
                    .revoke(f.f.authority.realm(), f.f.current.verifier())
                    .await
                    .unwrap()
            }
            "key" => {
                f.f.store
                    .disable_issuer_key(&f.f.authority, f.f.key.id())
                    .await
                    .unwrap()
            }
            "issuer" => {
                f.f.store
                    .disable_issuer_signing(&f.f.authority)
                    .await
                    .unwrap()
            }
            "owner" => {
                sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2").bind(f.f.authority.realm()).bind(f.f.owner).execute(&f.f.pool).await.unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            f.service()
                .introspect_access(
                    &f.authentication(),
                    &f.issued.access_token().into(),
                    "127.0.0.1"
                )
                .await
                .unwrap()
                .is_none()
        );
        // Possession revocation remains possible even after owner/source expiry.
        f.service()
            .revoke_access(
                &f.authentication(),
                &f.issued.access_token().into(),
                "127.0.0.1",
            )
            .await
            .unwrap();
        assert!(f.revoked().await.is_some());
    }
}

#[sqlx::test]
async fn changed_or_disabled_client_credentials_never_turn_into_inactive_success(pool: PgPool) {
    let f = Fixture::new(pool, true).await;
    let changed_secret = Secret::generate().unwrap();
    let changed =
        f.f.store
            .configure_issuer_client(
                &IssuerClientRegistration::confidential(
                    f.f.authority.realm(),
                    f.f.client.client(),
                    &["https://app.example/cb"],
                    &changed_secret,
                )
                .unwrap(),
            )
            .await
            .unwrap();
    assert_ne!(changed.revision(), f.f.client.revision());
    assert!(matches!(
        f.service()
            .introspect_access(
                &f.authentication(),
                &f.issued.access_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidClient)
    ));
    assert!(matches!(
        f.service()
            .revoke_access(
                &f.authentication(),
                &f.issued.access_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidClient)
    ));
    assert!(f.revoked().await.is_none());
    let current = IssuerClientAuthentication::basic(changed.client(), &changed_secret).unwrap();
    assert!(
        f.service()
            .introspect_access(&current, &f.issued.access_token().into(), "127.0.0.1")
            .await
            .unwrap()
            .is_none()
    );
    f.f.store
        .disable_issuer_client(changed.realm(), changed.client())
        .await
        .unwrap();
    assert!(matches!(
        f.service()
            .introspect_access(&current, &f.issued.access_token().into(), "127.0.0.1")
            .await,
        Err(IssuerTokenError::InvalidClient)
    ));
}
