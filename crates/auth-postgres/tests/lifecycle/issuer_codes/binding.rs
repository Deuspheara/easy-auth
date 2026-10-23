use super::*;
use auth_core::{Error, IssuerTokenError};

#[sqlx::test]
async fn private_consent_proofs_owner_session_preview_and_authority_are_not_interchangeable(
    pool: PgPool,
) {
    let f = Fixture::new(&pool, false).await;
    let pending = f.prepare().await.unwrap();
    let wrong = Secret::generate().unwrap();
    let same_owner = crate::support::signed_in(&f.store, f.realm, "owner@example.test").await;
    let other_owner = crate::support::signed_in(&f.store, f.realm, "other@example.test").await;
    for (current, browser, handle, id) in [
        (
            &wrong,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        ),
        (
            &same_owner,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        ),
        (
            &other_owner,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        ),
        (
            &f.current,
            &wrong,
            pending.handle(),
            pending.authorization(),
        ),
        (&f.current, &f.browser, &wrong, pending.authorization()),
        (&f.current, &f.browser, pending.handle(), Uuid::new_v4()),
    ] {
        assert!(matches!(
            f.service.preview(current, browser, handle, id).await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            f.service.approve(current, browser, handle, id).await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            f.service.cancel(current, browser, handle, id).await,
            Err(Error::Unauthorized)
        ));
    }
    for authority in [
        IssuerAuthority::new(f.realm, "https://other-issuer.example").unwrap(),
        IssuerAuthority::new(Uuid::new_v4(), "https://issuer.example").unwrap(),
    ] {
        let other = IssuerAuthorization::new(authority, f.store.clone());
        assert!(matches!(
            other
                .approve(
                    &f.current,
                    &f.browser,
                    pending.handle(),
                    pending.authorization()
                )
                .await,
            Err(Error::Unauthorized)
        ));
    }
    f.approve(&pending).await;
}

#[sqlx::test]
async fn wrong_pkce_client_code_and_actual_native_port_leave_original_code_usable(pool: PgPool) {
    let f = Fixture::new(&pool, true).await;
    let pending = f.prepare().await.unwrap();
    let code = f.approve(&pending).await;
    let wrong_code = Secret::generate().unwrap();
    let wrong_pkce =
        IssuerPkceVerifier::parse(Secret::generate().unwrap().expose().to_owned()).unwrap();
    for (code, redirect, pkce) in [
        (&wrong_code, f.redirect.as_str(), &f.pkce),
        (&code, "http://127.0.0.1:49153/callback", &f.pkce),
        (&code, f.redirect.as_str(), &wrong_pkce),
    ] {
        assert!(matches!(
            f.service
                .redeem(&f.authentication(), code, redirect, pkce, "127.0.0.1")
                .await,
            Err(IssuerTokenError::InvalidGrant)
        ));
    }
    let other = f
        .store
        .configure_issuer_client(
            &IssuerClientRegistration::public_native_loopback(
                f.realm,
                Uuid::new_v4(),
                &[&f.redirect],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let other_auth = IssuerClientAuthentication::public(other.client()).unwrap();
    assert!(matches!(
        f.service
            .redeem(&other_auth, &code, &f.redirect, &f.pkce, "127.0.0.1")
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
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
