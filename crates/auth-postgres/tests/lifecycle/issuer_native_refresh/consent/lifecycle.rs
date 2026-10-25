use super::*;
use auth_core::{IssuerClientAuthentication, IssuerTokenError};

#[sqlx::test]
async fn explicit_native_consent_keeps_original_bounds_and_cannot_enter_online_redemption(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let pending = f.prepare().await;
    assert!(pending.grant_expires_at_us() > pending.expires_at_us());
    assert_eq!(pending.idle_seconds(), 3600);
    assert_eq!(f.facts().await, (1, 1, 0, 0, 0));
    let before = f.facts().await;
    let preview = f
        .service
        .preview(
            &f.current,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        )
        .await
        .unwrap();
    assert_eq!(preview.client, pending.client());
    assert_eq!(preview.redirect_uri, pending.redirect_uri());
    assert_eq!(preview.grant_expires_at_us, pending.grant_expires_at_us());
    assert_eq!(f.facts().await, before);
    assert!(matches!(
        f.online()
            .preview(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.online()
            .approve(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.online()
            .cancel(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    let returned = f
        .service
        .approve(
            &f.current,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        )
        .await
        .unwrap();
    let url = url::Url::parse(returned.url()).unwrap();
    assert_eq!(url.port(), Some(41002));
    let fields: std::collections::BTreeMap<_, _> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields["state"], "owned-state");
    assert_eq!(fields["iss"], f.policy.authority().issuer());
    let code = Secret::parse(fields["code"].clone()).unwrap();
    let authentication = IssuerClientAuthentication::public(f.policy.client().client()).unwrap();
    assert!(matches!(
        f.online()
            .redeem(
                &authentication,
                &code,
                pending.redirect_uri(),
                &f.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    let (marker,status,original,approved,sidecar_approved,code_expiry):(bool,String,i64,i64,i64,i64)=sqlx::query_as("SELECT a.native_refresh,a.status,c.grant_expires_at_us,a.approved_at_us,c.approved_at_us,a.code_expires_at_us FROM auth_issuer_authorizations a JOIN auth_issuer_native_consents c ON (a.realm_id,a.id)=(c.realm_id,c.authorization_id) WHERE a.realm_id=$1")
        .bind(f.policy.authority().realm()).fetch_one(&f.pool).await.unwrap();
    assert!(marker);
    assert_eq!(status, "approved");
    assert_eq!(original, pending.grant_expires_at_us());
    assert_eq!(approved, sidecar_approved);
    assert!(code_expiry <= approved + 60_000_000 && code_expiry <= pending.expires_at_us());
    assert_eq!(f.facts().await, (1, 1, 1, 0, 1));
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
            .cancel(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await
            .is_err()
    );
    f.store
        .authenticate(f.policy.authority().realm(), f.current.verifier())
        .await
        .unwrap();
}

#[sqlx::test]
async fn native_cancellation_after_policy_disable_erases_only_pending_consent_and_allows_no_authority(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let pending = f.prepare().await;
    f.store
        .disable_issuer_native_refresh_policy(f.policy.authority(), f.policy.client().client())
        .await
        .unwrap();
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
    let returned = f
        .service
        .cancel(
            &f.current,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        )
        .await
        .unwrap();
    assert!(returned.url().contains("error=access_denied"));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.store
        .authenticate(f.policy.authority().realm(), f.current.verifier())
        .await
        .unwrap();
    assert!(
        f.service
            .cancel(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await
            .is_err()
    );
}

#[sqlx::test]
async fn native_pending_admission_and_allocation_share_existing_bounded_quota(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.prepare().await;
    let _b = f.prepare().await;
    let _c = f.prepare().await;
    assert!(matches!(
        f.prepare_with("openid offline_access", "consent").await,
        Err(Error::RateLimited)
    ));
    f.service
        .cancel(&f.current, &f.browser, a.handle(), a.authorization())
        .await
        .unwrap();
    let _replacement = f.prepare().await;
    assert_eq!(f.facts().await, (3, 3, 0, 0, 0));
}
