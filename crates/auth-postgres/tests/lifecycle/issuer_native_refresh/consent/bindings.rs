use super::*;

#[sqlx::test]
async fn native_offline_scope_prompt_owner_and_private_bindings_cannot_be_substituted(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    for (scope, prompt) in [
        ("openid", "consent"),
        ("offline_access", "consent"),
        ("openid offline_access", "none"),
        ("openid offline_access", ""),
        ("offline_access openid", "consent"),
    ] {
        assert!(matches!(
            f.prepare_with(scope, prompt).await,
            Err(Error::InvalidInput)
        ));
    }
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    let a = f.prepare().await;
    let b = f.prepare().await;
    let stranger =
        crate::support::signed_in(&f.store, f.policy.authority().realm(), "other@example.test")
            .await;
    let wrong = Secret::generate().unwrap();
    for (current, browser, handle, id) in [
        (&stranger, &f.browser, a.handle(), a.authorization()),
        (&f.current, &wrong, a.handle(), a.authorization()),
        (&f.current, &f.browser, &wrong, a.authorization()),
        (&f.current, &f.browser, a.handle(), b.authorization()),
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
    let alien =
        auth_core::IssuerAuthority::new(Uuid::new_v4(), f.policy.authority().issuer()).unwrap();
    let alien = IssuerNativeAuthorization::new(alien, f.store.clone());
    assert!(
        alien
            .preview(&f.current, &f.browser, a.handle(), a.authorization())
            .await
            .is_err()
    );
    let other_issuer =
        auth_core::IssuerAuthority::new(f.policy.authority().realm(), "https://other.example")
            .unwrap();
    let other = IssuerNativeAuthorization::new(other_issuer, f.store.clone());
    assert!(
        other
            .approve(&f.current, &f.browser, a.handle(), a.authorization())
            .await
            .is_err()
    );
    assert_eq!(f.facts().await, (2, 2, 0, 0, 0));
    f.service
        .approve(&f.current, &f.browser, a.handle(), a.authorization())
        .await
        .unwrap();
}

#[sqlx::test]
async fn native_proposal_retains_policy_revision_and_absolute_cap_after_reconfiguration(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let pending = f.prepare().await;
    let next = f
        .store
        .configure_issuer_native_refresh_policy(&f.policy)
        .await
        .unwrap();
    assert_ne!(next.revision(), f.policy.revision());
    assert!(
        f.service
            .preview(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await
            .is_err()
    );
    assert!(
        f.service
            .approve(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await
            .is_err()
    );
    f.service
        .cancel(
            &f.current,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        )
        .await
        .unwrap();
    let pending = f.prepare().await;
    sqlx::query("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE realm_id=$1 AND user_id=$2")
        .bind(f.policy.authority().realm()).bind(f.owner).execute(&f.pool).await.unwrap();
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
    assert_eq!(f.facts().await, (1, 1, 0, 0, 0));
    f.service
        .cancel(
            &f.current,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        )
        .await
        .unwrap();
}
