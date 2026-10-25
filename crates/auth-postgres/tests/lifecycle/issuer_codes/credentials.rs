use super::*;
use auth_core::{Error, IssuerTokenError};

#[sqlx::test]
async fn confidential_authentication_is_current_and_required_even_for_unknown_codes(pool: PgPool) {
    let mut f = Fixture::new(&pool, false).await;
    let secret = Secret::generate().unwrap();
    f.client = f
        .store
        .configure_issuer_client(
            &IssuerClientRegistration::confidential(
                f.realm,
                f.client.client(),
                &[&f.redirect],
                &secret,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let pending = f.prepare().await.unwrap();
    let code = f.approve(&pending).await;
    let bad_secret = Secret::generate().unwrap();
    let wrong = IssuerClientAuthentication::basic(f.client.client(), &bad_secret).unwrap();
    let right = IssuerClientAuthentication::basic(f.client.client(), &secret).unwrap();
    let unknown = Secret::generate().unwrap();
    for presented in [&code, &unknown] {
        for auth in [&wrong, &f.authentication()] {
            assert!(matches!(
                f.service
                    .redeem(auth, presented, &f.redirect, &f.pkce, "127.0.0.1")
                    .await,
                Err(IssuerTokenError::InvalidClient)
            ));
        }
    }
    assert!(matches!(
        f.service
            .redeem(
                &wrong,
                &code,
                "https://wrong.example/cb",
                &f.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidClient)
    ));
    assert!(matches!(
        f.service
            .redeem(&right, &unknown, &f.redirect, &f.pkce, "127.0.0.1")
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    f.service
        .redeem(&right, &code, &f.redirect, &f.pkce, "127.0.0.1")
        .await
        .unwrap();
}

#[sqlx::test]
async fn stale_and_disabled_client_state_revoked_and_old_sessions_fail_closed(pool: PgPool) {
    let mut f = Fixture::new(&pool, false).await;
    let pending = f.prepare().await.unwrap();
    f.client = f.store.configure_issuer_client(&f.client).await.unwrap();
    assert!(matches!(
        f.service
            .approve(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let second = f.prepare().await.unwrap();
    let code = f.approve(&second).await;
    f.store
        .disable_issuer_client(f.realm, f.client.client())
        .await
        .unwrap();
    assert!(matches!(
        f.service
            .redeem(
                &f.authentication(),
                &code,
                &f.redirect,
                &f.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidClient)
    ));
    f.client = f.store.configure_issuer_client(&f.client).await.unwrap();
    f.store.enable_issuer_client(&f.client).await.unwrap();
    let fresh_pending = f.prepare().await.unwrap();
    let code = f.approve(&fresh_pending).await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE realm_id=$1")
        .bind(f.realm).execute(&pool).await.unwrap();
    assert!(matches!(f.prepare().await, Err(Error::Unauthorized)));
    assert!(matches!(
        f.service
            .redeem(
                &f.authentication(),
                &code,
                &f.redirect,
                &f.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1")
        .bind(f.realm)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(f.prepare().await, Err(Error::Unauthorized)));
}

#[sqlx::test]
async fn foreign_authority_and_realm_cannot_redeem_local_code(pool: PgPool) {
    let f = Fixture::new(&pool, false).await;
    let pending = f.prepare().await.unwrap();
    let code = f.approve(&pending).await;
    let other = Fixture::new(&pool, false).await;
    let registration =
        IssuerClientRegistration::public(other.realm, f.client.client(), &[&f.redirect]).unwrap();
    let configured = other
        .store
        .configure_issuer_client(&registration)
        .await
        .unwrap();
    assert_eq!(configured.realm(), other.realm);
    let wrong_issuer = IssuerAuthorization::new(
        IssuerAuthority::new(f.realm, "https://other-issuer.example").unwrap(),
        f.store.clone(),
    );
    for service in [&other.service, &wrong_issuer] {
        assert!(matches!(
            service
                .redeem(
                    &f.authentication(),
                    &code,
                    &f.redirect,
                    &f.pkce,
                    "127.0.0.1"
                )
                .await,
            Err(IssuerTokenError::InvalidGrant)
        ));
    }
    f.service
        .redeem(
            &f.authentication(),
            &code,
            &f.redirect,
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
}
