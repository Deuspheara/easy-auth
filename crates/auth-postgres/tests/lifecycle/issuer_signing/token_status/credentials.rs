use super::*;
use auth_core::{IssuerAuthority, IssuerTokenError, IssuerTokenStatusRequest};
use uuid::Uuid;

#[sqlx::test]
async fn introspection_requires_actual_basic_and_projects_only_its_live_audience(pool: PgPool) {
    let f = Fixture::new(pool, true).await;
    let service = f.service();
    let before: serde_json::Value =
        sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(s)) FROM auth_sessions s")
            .fetch_one(&f.f.pool)
            .await
            .unwrap();
    let active = service
        .introspect_access(
            &f.authentication(),
            &f.issued.access_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.issuer(), f.f.authority.issuer());
    assert_eq!(active.client(), f.f.client.client());
    assert_ne!(active.subject(), f.f.owner);
    assert!(
        active.issued_at_us() <= active.checked_at_us()
            && active.checked_at_us() < active.expires_at_us()
    );
    assert!(active.expires_at_us() - active.issued_at_us() <= 60_000_000);
    let after: serde_json::Value =
        sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(s)) FROM auth_sessions s")
            .fetch_one(&f.f.pool)
            .await
            .unwrap();
    assert!(
        before == after,
        "read-only introspection must not extend session idle time"
    );
    assert!(
        service
            .introspect_access(
                &f.authentication(),
                &IssuerPresentedToken::parse("unknown-opaque-token".to_owned()).unwrap(),
                "127.0.0.1"
            )
            .await
            .unwrap()
            .is_none()
    );
    for authentication in [
        f.f.authentication(),
        IssuerClientAuthentication::basic(f.f.client.client(), &Secret::generate().unwrap())
            .unwrap(),
    ] {
        for token in [
            IssuerPresentedToken::from(f.issued.access_token()),
            IssuerPresentedToken::parse("unknown-opaque-token".to_owned()).unwrap(),
        ] {
            assert!(matches!(
                service
                    .introspect_access(&authentication, &token, "127.0.0.1")
                    .await,
                Err(IssuerTokenError::InvalidClient)
            ));
        }
    }
    assert_eq!(f.f.facts().await, (1, 1, 1, 1));
}

#[sqlx::test]
async fn another_client_realm_or_issuer_never_observes_or_revokes_this_access(pool: PgPool) {
    let f = Fixture::new(pool, true).await;
    let other_secret = Secret::generate().unwrap();
    let other =
        f.f.store
            .configure_issuer_client(
                &IssuerClientRegistration::confidential(
                    f.f.authority.realm(),
                    Uuid::new_v4(),
                    &["https://other.example/cb"],
                    &other_secret,
                )
                .unwrap(),
            )
            .await
            .unwrap();
    let authentication = IssuerClientAuthentication::basic(other.client(), &other_secret).unwrap();
    assert!(
        f.service()
            .introspect_access(
                &authentication,
                &f.issued.access_token().into(),
                "127.0.0.1"
            )
            .await
            .unwrap()
            .is_none()
    );
    f.service()
        .revoke_access(
            &authentication,
            &f.issued.access_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    let issuer =
        IssuerAuthority::new(f.f.authority.realm(), "https://other-issuer.example").unwrap();
    let other_issuer = IssuerTokenManagement::new(issuer, f.f.store.clone());
    assert!(
        other_issuer
            .introspect_access(
                &f.authentication(),
                &f.issued.access_token().into(),
                "127.0.0.1"
            )
            .await
            .unwrap()
            .is_none()
    );
    other_issuer
        .revoke_access(
            &f.authentication(),
            &f.issued.access_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    let realm = Uuid::new_v4();
    f.f.store.ensure_realm(realm).await.unwrap();
    let foreign =
        f.f.store
            .configure_issuer_client(
                &IssuerClientRegistration::confidential(
                    realm,
                    f.f.client.client(),
                    &["https://app.example/cb"],
                    &other_secret,
                )
                .unwrap(),
            )
            .await
            .unwrap();
    let authentication =
        IssuerClientAuthentication::basic(foreign.client(), &other_secret).unwrap();
    let management = IssuerTokenManagement::new(
        IssuerAuthority::new(realm, f.f.authority.issuer()).unwrap(),
        f.f.store.clone(),
    );
    assert!(
        management
            .introspect_access(
                &authentication,
                &f.issued.access_token().into(),
                "127.0.0.1"
            )
            .await
            .unwrap()
            .is_none()
    );
    management
        .revoke_access(
            &authentication,
            &f.issued.access_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    let cross = IssuerTokenStatusRequest {
        authority: &f.f.authority,
        client: &foreign,
        authentication: &authentication,
        token: f.issued.access_token().verifier(),
    };
    assert!(matches!(
        f.f.store.revoke_issuer_access(&cross).await,
        Err(IssuerTokenError::InvalidClient)
    ));
    assert!(matches!(
        f.f.store.introspect_issuer_access(&cross).await,
        Err(IssuerTokenError::InvalidClient)
    ));
    assert!(f.revoked().await.is_none());
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
}

#[sqlx::test]
async fn introspection_storage_fault_is_unavailable_and_not_inactive_success(pool: PgPool) {
    let f = Fixture::new(pool, true).await;
    sqlx::query("ALTER TABLE auth_issuer_access_tokens RENAME TO test_unavailable_access")
        .execute(&f.f.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.service()
            .introspect_access(
                &f.authentication(),
                &f.issued.access_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::Unavailable)
    ));
    assert!(matches!(
        f.service()
            .revoke_access(
                &f.authentication(),
                &f.issued.access_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::Unavailable)
    ));
}
