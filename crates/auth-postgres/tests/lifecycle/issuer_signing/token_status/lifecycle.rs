use super::*;
use auth_core::{Error, IssuerTokenError, Repository};

#[sqlx::test]
async fn public_possession_revokes_only_its_access_and_never_authenticates_introspection(
    pool: PgPool,
) {
    let f = Fixture::new(pool, false).await;
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
    f.service()
        .revoke_access(
            &f.authentication(),
            &IssuerPresentedToken::parse("unknown-opaque-token".to_owned()).unwrap(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert!(f.revoked().await.is_none());
    f.service()
        .revoke_access(
            &f.authentication(),
            &f.issued.access_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    let first = f.revoked().await.unwrap();
    f.service()
        .revoke_access(
            &f.authentication(),
            &f.issued.access_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(f.revoked().await, Some(first));
    assert!(matches!(
        f.f.store
            .authenticate(f.f.authority.realm(), f.issued.access_token().verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    f.f.store
        .authenticate(f.f.authority.realm(), f.f.current.verifier())
        .await
        .unwrap();
    assert_eq!(f.f.facts().await, (1, 1, 1, 1));
}

#[sqlx::test]
async fn explicit_revocation_stays_inactive_and_does_not_change_original_code_or_audit(
    pool: PgPool,
) {
    let f = Fixture::new(pool, true).await;
    let before: serde_json::Value =
        sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(a)) FROM auth_issuer_authorizations a")
            .fetch_one(&f.f.pool)
            .await
            .unwrap();
    f.service()
        .revoke_access(
            &f.authentication(),
            &f.issued.access_token().into(),
            "127.0.0.1",
        )
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
    let after: serde_json::Value =
        sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(a)) FROM auth_issuer_authorizations a")
            .fetch_one(&f.f.pool)
            .await
            .unwrap();
    assert!(before == after);
    assert_eq!(f.f.facts().await, (1, 1, 1, 1));
    f.f.store
        .disable_issuer_signing(&f.f.authority)
        .await
        .unwrap();
    let revision =
        f.f.store
            .activate_issuer_key(&f.f.authority, f.f.key.id())
            .await
            .unwrap();
    f.f.store
        .enable_issuer_signing(&f.f.authority, revision)
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
